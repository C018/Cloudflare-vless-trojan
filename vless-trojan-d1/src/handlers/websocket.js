/**
 * WebSocket inbound handler: VLESS / Trojan protocol dispatch, TCP & UDP forwarding
 */

import { processVlessHeader } from '../protocol/vless.js';
import { processTrojanHeader, isTrojanLike } from '../protocol/trojan.js';
import { handleTcpOutbound, resolveOutbound } from '../outbound/tcp.js';
import { vlessOutboundConnect } from '../outbound/vless.js';
import { safeCloseWebSocket } from '../outbound/stream.js';
import { decideRoute } from '../routing/engine.js';

/**
 * 将 ws 消息统一归一化为 ArrayBuffer（支持 ArrayBuffer / 视图 / 文本帧）
 */
function normalizeToArrayBuffer(data) {
	if (data instanceof ArrayBuffer) return data;
	if (ArrayBuffer.isView(data)) {
		return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
	}
	if (typeof data === 'string') return new TextEncoder().encode(data).buffer;
	return null;
}

/**
 * 将 ws 消息统一归一化为 Uint8Array（用于写入 socket writable）
 */
function normalizeToUint8Array(data) {
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return new TextEncoder().encode(data);
	return null;
}

/**
 * 处理 WebSocket 升级请求（代理入口）
 */
export async function handleWebSocketUpgrade(request, config, env) {
	const upgrade = request.headers.get('Upgrade');
	if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
		return new Response('Expected WebSocket', { status: 400 });
	}
	const [client, server] = Object.values(new WebSocketPair());
	server.accept();

	const log = (...args) => console.log('[ws]', ...args);
	handleWSConnection(server, config, env, log).catch((e) => {
		log(`ws handler error: ${e.message || e}`);
		safeCloseWebSocket(server);
	});

	return new Response(null, { status: 101, webSocket: client });
}

async function handleWSConnection(ws, config, env, log) {
	let protocolBuffer;
	try {
		protocolBuffer = await readFirstPacket(ws, log);
	} catch (e) {
		log(`read first packet error: ${e.message}`);
		safeCloseWebSocket(ws);
		return;
	}
	if (!protocolBuffer) {
		safeCloseWebSocket(ws);
		return;
	}

	let headerResult;
	let userRecord = null;
	let kind = 'vless'; // vless | trojan

	if (isTrojanLike(protocolBuffer)) {
		headerResult = await processTrojanHeader(protocolBuffer, config.passwordSet);
		if (headerResult.hasError) {
			log(`trojan header error: ${headerResult.message}`);
			safeCloseWebSocket(ws);
			return;
		}
		kind = 'trojan';
		userRecord = config.trojanIndex[headerResult.userPassword] || null;
	} else {
		headerResult = processVlessHeader(protocolBuffer, config.uuidSet);
		if (headerResult.hasError) {
			log(`vless header error: ${headerResult.message}`);
			safeCloseWebSocket(ws);
			return;
		}
		userRecord = config.vlessIndex[headerResult.userUuid] || null;
	}

	const { addressType, addressRemote, portRemote, isUDP } = headerResult;
	const firstPayload = new Uint8Array(protocolBuffer.slice(headerResult.rawDataIndex));

	let route;
	try {
		route = await decideRoute(config, addressType, addressRemote);
	} catch (e) {
		log(`route error: ${e.message}`);
		safeCloseWebSocket(ws);
		return;
	}

	if (isUDP) {
		await handleUDP(ws, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log);
	} else {
		await handleTCP(ws, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log);
	}
}

function readFirstPacket(ws, log) {
	return new Promise((resolve, reject) => {
		let done = false;
		const cleanup = () => {
			ws.removeEventListener('message', onMessage);
			ws.removeEventListener('close', onClose);
			ws.removeEventListener('error', onError);
		};
		const onMessage = (event) => {
			if (done) return;
			done = true;
			cleanup();
			resolve(normalizeToArrayBuffer(event.data));
		};
		const onClose = () => {
			if (done) return;
			done = true;
			cleanup();
			resolve(null);
		};
		const onError = (err) => {
			if (done) return;
			done = true;
			cleanup();
			reject(err);
		};
		ws.addEventListener('message', onMessage);
		ws.addEventListener('close', onClose);
		ws.addEventListener('error', onError);
		setTimeout(() => {
			if (!done) { done = true; cleanup(); resolve(null); }
		}, 15000);
	});
}

async function handleTCP(ws, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log) {
	const outbound = resolveOutbound(config, route.outbound);
	const rawClientData = firstPayload && firstPayload.length > 0 ? firstPayload : new Uint8Array(0);

	const attempts = [outbound];
	if (outbound !== 'direct' && outbound !== 'reject') attempts.push('direct');

	let remoteSocket = null;
	let lastError = null;
	for (const ob of attempts) {
		try {
			remoteSocket = await handleTcpOutbound({
				config, outbound: ob, addressType, addressRemote, portRemote, rawClientData, log
			});
		} catch (e) {
			lastError = e;
			remoteSocket = null;
		}
		if (remoteSocket) break;
	}

	if (!remoteSocket) {
		log(`tcp connect failed: ${lastError ? lastError.message : 'no outbound available'}`);
		safeCloseWebSocket(ws);
		return;
	}

	let upBytes = 0;
	let downBytes = 0;
	let closed = false;
	const writer = remoteSocket.writable.getWriter();

	// ws -> remote（客户端上行）
	const onWsMessage = (event) => {
		if (closed) return;
		const data = normalizeToUint8Array(event.data);
		if (!data || data.length === 0) return;
		upBytes += data.byteLength;
		try { writer.write(data).catch(() => {}); } catch (e) { /* ignore */ }
	};
	ws.addEventListener('message', onWsMessage);

	// remote -> ws（远端下行）
	try {
		const reader = remoteSocket.readable.getReader();
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value && value.byteLength > 0) {
				downBytes += value.byteLength;
				if (ws.readyState === 1) {
					ws.send(value);
				}
			}
		}
	} catch (e) {
		log(`tcp remote read error: ${e.message}`);
	}

	closed = true;
	ws.removeEventListener('message', onWsMessage);
	try { writer.releaseLock(); } catch (e) { /* ignore */ }
	try { await remoteSocket.writable.close(); } catch (e) { /* ignore */ }
	try { ws.close(); } catch (e) { /* ignore */ }

	await recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
}

async function handleUDP(ws, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log) {
	// UDP 出站：系统设置 udp_outbound 指定出站名，从出站代理中匹配该名称的出站（仅 vless 支持 UDP）
	let vlessOb = null;
	const udpName = (config.udpOutbound || '').trim();
	if (udpName) {
		const ob = config.outboundByName[udpName];
		if (ob && ob.type === 'vless') {
			vlessOb = ob;
		} else {
			log(`udp outbound '${udpName}' not found or not vless (only vless supports udp)`);
			safeCloseWebSocket(ws);
			return;
		}
	} else {
		// 未配置 udp 出站代理：优先路由出站（若为 vless），否则取第一个 vless 出站
		if (route.outbound && route.outbound !== 'direct' && route.outbound !== 'reject') {
			const ob = resolveOutbound(config, route.outbound);
			if (ob !== 'direct' && ob !== 'reject' && ob.type === 'vless') vlessOb = ob;
		}
		if (!vlessOb) vlessOb = config.outbounds.find((o) => o.type === 'vless');
	}
	if (!vlessOb) {
		log('udp requires a vless outbound, none configured');
		safeCloseWebSocket(ws);
		return;
	}

	const firstFrame = firstPayload && firstPayload.length > 0 ? firstPayload : new Uint8Array([0, 0]);
	const conn = await vlessOutboundConnect(
		{ address: vlessOb.address, port: Number(vlessOb.port), uuid: vlessOb.uuid, path: vlessOb.path, tls: !!vlessOb.tls, sni: vlessOb.sni || '' },
		0x02, addressType, addressRemote, portRemote, firstFrame, log
	);
	if (!conn) {
		log('udp vless outbound connect failed');
		safeCloseWebSocket(ws);
		return;
	}

	let upBytes = 0;
	let downBytes = 0;
	let closed = false;
	const writer = conn.writable.getWriter();

	const onWsMessage = (event) => {
		if (closed) return;
		const data = normalizeToUint8Array(event.data);
		if (!data || data.length === 0) return;
		upBytes += data.byteLength;
		try { writer.write(data).catch(() => {}); } catch (e) { /* ignore */ }
	};
	ws.addEventListener('message', onWsMessage);

	try {
		const outReader = conn.readable.getReader();
		while (true) {
			const { done, value } = await outReader.read();
			if (done) break;
			if (value && value.byteLength > 0) {
				downBytes += value.byteLength;
				if (ws.readyState === 1) ws.send(value);
			}
		}
	} catch (e) {
		log(`udp read error: ${e.message}`);
	}

	closed = true;
	ws.removeEventListener('message', onWsMessage);
	try { writer.releaseLock(); } catch (e) { /* ignore */ }
	try { await conn.writable.close(); } catch (e) { /* ignore */ }
	safeCloseWebSocket(ws);

	await recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
}

/**
 * 连接关闭后异步累加流量到 D1
 */
async function recordTraffic(config, userRecord, kind, upBytes, downBytes, log) {
	if (!userRecord) return;
	const table = kind === 'vless' ? 'vless_users' : 'trojan_users';
	try {
		await config.env.DB.prepare(
			`UPDATE ${table} SET up = up + ?, down = down + ? WHERE id = ?`
		).bind(upBytes, downBytes, userRecord.id).run();
	} catch (e) {
		log(`record traffic error: ${e.message}`);
	}
}
