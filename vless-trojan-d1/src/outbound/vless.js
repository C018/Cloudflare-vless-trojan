/**
 * VLESS outbound proxy (multi-transport)
 * 支持 raw / ws / grpc / httpupgrade 四种传输方式，统一建连后发送 VLESS 请求头+首包，
 * 解析并剥离响应头（ws/grpc 由其封装层处理），返回 {readable, writable, closed}。
 */

import {
	WS_READY_STATE_OPEN,
	VLESS_CMD_TCP,
	VLESS_CMD_UDP,
	OUTBOUND_TRANSPORTS,
	OUTBOUND_TRANSPORT_DEFAULT
} from '../config/constants.js';
import { makeVlessRequestHeader } from '../protocol/vless.js';
import { safeCloseWebSocket } from './stream.js';
import { rawConnect } from './vless-raw.js';
import { httpUpgradeConnect } from './vless-httpupgrade.js';
import { grpcConnect } from './vless-grpc.js';

export const VLESS_OUTBOUND_TIMEOUT = 10000;

/**
 * 建立 VLESS 出站连接
 * @param {Object} config {address, port, uuid, path, tls, sni, transport}
 * @param {number} command VLESS_CMD_TCP / VLESS_CMD_UDP
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {Uint8Array} rawClientData
 * @param {Function} log
 * @returns {Promise<{readable:ReadableStream,writable:WritableStream,closed:Promise<void>}|null>}
 */
export async function vlessOutboundConnect(config, command, addressType, addressRemote, portRemote, rawClientData, log) {
	const transport = config.transport || OUTBOUND_TRANSPORT_DEFAULT;
	if (!OUTBOUND_TRANSPORTS.includes(transport)) {
		log(`[VLESS] unsupported transport: ${transport}`);
		return null;
	}

	let link = null;
	try {
		if (transport === 'ws') {
			link = await wsConnect(config, log);
		} else if (transport === 'raw') {
			link = await rawConnect(config, log);
		} else if (transport === 'httpupgrade') {
			link = await httpUpgradeConnect(config, log);
		} else if (transport === 'grpc') {
			link = await grpcConnect(config, log);
		}
	} catch (err) {
		log(`[VLESS/${transport}] connect failed: ${err.message}`);
		return null;
	}
	if (!link) return null;

	const vlessHeader = makeVlessRequestHeader(command, addressType, addressRemote, portRemote, config.uuid);
	const clientData = rawClientData instanceof Uint8Array ? rawClientData : new Uint8Array(rawClientData || 0);
	const firstPacket = new Uint8Array(vlessHeader.length + clientData.length);
	firstPacket.set(vlessHeader, 0);
	firstPacket.set(clientData, vlessHeader.length);
	try {
		await link.send(firstPacket);
	} catch (e) {
		log(`[VLESS/${transport}] send header failed: ${e.message}`);
		try { if (link.close) await link.close(); } catch (err) { /* ignore */ }
		return null;
	}

	return { readable: link.readable, writable: link.writable, closed: link.closed };
}

/**
 * WebSocket 传输建连（原 vless.js 逻辑）
 * @returns {Promise<{readable,writable,closed,send:(d:Uint8Array)=>Promise<void>}|null>}
 */
async function wsConnect(config, log) {
	const security = config.tls ? 'wss' : 'ws';
	const path = config.path && config.path.startsWith('/') ? config.path : `/${config.path || ''}`;
	// SNI 支持：配置 sni 时以其作为连接主机名（Workers 平台 TLS SNI 跟随连接主机，无法与连接地址分离）
	const wsHost = config.sni && config.sni !== '' ? config.sni : config.address;
	const wsURL = `${security}://${wsHost}:${config.port}${path}`;

	let ws;
	try {
		ws = new WebSocket(wsURL);
	} catch (err) {
		log(`[VLESS/ws] create ws failed: ${err.message}`);
		return null;
	}

	let closedResolve;
	const closedPromise = new Promise((resolve) => { closedResolve = resolve; });

	try {
		await new Promise((resolve, reject) => {
			const timeoutId = setTimeout(() => reject(new Error('Connection timeout')), VLESS_OUTBOUND_TIMEOUT);
			ws.addEventListener('open', () => { clearTimeout(timeoutId); resolve(); });
			ws.addEventListener('close', (event) => { clearTimeout(timeoutId); reject(new Error(`closed ${event.code}`)); });
			ws.addEventListener('error', () => { clearTimeout(timeoutId); reject(new Error('ws error')); });
		});
	} catch (err) {
		log(`[VLESS/ws] connect failed: ${err.message}`);
		try { ws.close(); } catch (e) { /* ignore */ }
		closedResolve();
		return null;
	}

	ws.addEventListener('close', () => closedResolve());
	ws.addEventListener('error', () => { /* ignore */ });

	const writableStream = new WritableStream({
		write(chunk) {
			if (ws.readyState === WS_READY_STATE_OPEN) {
				ws.send(chunk);
			}
		},
		close() { safeCloseWebSocket(ws); },
		abort() { safeCloseWebSocket(ws); }
	});

	let headerStripped = false;
	const readableStream = new ReadableStream({
		start(controller) {
			ws.addEventListener('message', (event) => {
				let data;
				try {
					if (event.data instanceof ArrayBuffer) {
						data = new Uint8Array(event.data);
					} else if (ArrayBuffer.isView(event.data)) {
						data = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
					} else if (typeof event.data === 'string') {
						data = new TextEncoder().encode(event.data);
					} else {
						data = null;
					}
				} catch (e) {
					data = null;
				}
				if (!data) return;
				if (!headerStripped) {
					headerStripped = true;
					if (data.length >= 2) {
						const addonLen = data[1];
						if (data.length > 2 + addonLen) {
							data = data.slice(2 + addonLen);
						} else {
							return; // header only
						}
					}
				}
				if (data.length > 0) {
					try { controller.enqueue(data); } catch (e) { /* ignore */ }
				}
			});
			ws.addEventListener('close', () => { try { controller.close(); } catch (e) { /* ignore */ } });
			ws.addEventListener('error', (err) => { try { controller.error(err); } catch (e) { /* ignore */ } });
		},
		cancel() { safeCloseWebSocket(ws); }
	});

	return {
		readable: readableStream,
		writable: writableStream,
		closed: closedPromise,
		send: async (data) => {
			if (ws.readyState !== WS_READY_STATE_OPEN) {
				throw new Error(`ws not open (state=${ws.readyState})`);
			}
			ws.send(data);
		}
	};
}

/**
 * 判断出站对象是否具备 UDP 能力
 */
export function outboundSupportsUDP(outbound) {
	return outbound && outbound.type === 'vless';
}

export { VLESS_CMD_TCP, VLESS_CMD_UDP };
