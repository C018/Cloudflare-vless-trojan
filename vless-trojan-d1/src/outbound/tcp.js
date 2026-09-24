/**
 * TCP outbound dispatcher
 * 按分流选出的出站建立 TCP 隧道；vless 出站返回流式对象，其余返回 Socket
 */

import { vlessOutboundConnect } from './vless.js';
import { socks5Connect, parseSocks5Address } from './socks5.js';
import { httpConnect, parseHttpAddress } from './http.js';
import { OUTBOUND_DIRECT, OUTBOUND_REJECT, OUTBOUND_SOCKS5, OUTBOUND_HTTP, OUTBOUND_VLESS } from '../config/constants.js';

/**
 * 直连：默认直连目标端点；若系统设置配置了 proxyip（且默认出站为 direct），
 * 则端点替换为 proxyip:port 建立裸 TCP 连接（CF 代理 IP，用于访问 Cloudflare 相关网站，仅 TCP）
 * @param {Object} config
 * @param {string} hostname
 * @param {number} port
 * @param {Uint8Array} initialData
 */
async function directConnect(config, hostname, port, initialData, log) {
	const useProxyIp = config.proxyipHost && !config.proxyipDisabled;
	const connHost = useProxyIp ? config.proxyipHost : hostname;
	const connPort = useProxyIp ? Number(config.proxyipPort || 443) : port;
	const socket = globalThis.connect ? globalThis.connect({ hostname: connHost, port: connPort }) : undefined;
	if (!socket) {
		log('connect unavailable');
		return null;
	}
	if (initialData && initialData.length > 0) {
		// 必须在返回前完成写入并释放锁，否则调用方后续 getWriter 会报 WritableStream locked
		const writer = socket.writable.getWriter();
		try {
			await writer.write(initialData);
		} catch (e) {
			log(`direct initial write error: ${e.message}`);
		} finally {
			try { writer.releaseLock(); } catch (e) { /* ignore */ }
		}
	}
	return socket;
}

/**
 * 选择 vless 出站配置（支持多个 vless 出站轮换）
 * @param {Object} config 请求级配置
 * @returns {Array<Object>} vless 出站列表
 */
function vlessOutboundCandidates(config) {
	return config.outbounds.filter((o) => o.type === OUTBOUND_VLESS);
}

/**
 * 建立 TCP 出站
 * @param {Object} args
 * @param {Object} args.config 请求级配置
 * @param {Object} args.outbound 选中的出站（direct/reject/socks5/http/vless 行）
 * @param {number} args.addressType
 * @param {string} args.addressRemote
 * @param {number} args.portRemote
 * @param {Uint8Array} args.rawClientData
 * @param {Function} args.log
 * @param {boolean} args.isUDP
 * @returns {Promise<Object|null>} {readable,writable,closed} 或 null
 */
export async function handleTcpOutbound(args) {
	const { config, outbound, addressType, addressRemote, portRemote, rawClientData, log, isUDP } = args;

	// 未命中规则时 default_outbound 可能是 'direct' 或出站 name
	let ob = outbound;
	if (!ob || ob === OUTBOUND_DIRECT) {
		return directConnect(config, addressRemote, portRemote, rawClientData, log);
	}
	if (ob === OUTBOUND_REJECT) {
		log('rejected by routing rule');
		return null;
	}

	switch (ob.type) {
		case OUTBOUND_DIRECT:
			return directConnect(config, addressRemote, portRemote, rawClientData, log);

		case OUTBOUND_SOCKS5: {
			let parsed;
			try {
				parsed = parseSocks5Address(ob.address, { username: ob.username, password: ob.password, port: ob.port });
			} catch (e) {
				log(`bad socks5 address: ${e.message}`);
				return null;
			}
			const socket = await socks5Connect(addressType, addressRemote, portRemote, log, parsed, globalThis.connect);
			if (!socket) return null;
			if (rawClientData && rawClientData.length > 0) {
				const writer = socket.writable.getWriter();
				try {
					await writer.write(rawClientData);
				} catch (e) {
					log(`socks5 write error: ${e.message}`);
				} finally {
					try { writer.releaseLock(); } catch (err) { /* ignore */ }
				}
			}
			return socket;
		}

		case OUTBOUND_HTTP: {
			let parsed;
			try {
				parsed = parseHttpAddress(ob.address, { username: ob.username, password: ob.password, port: ob.port });
			} catch (e) {
				log(`bad http address: ${e.message}`);
				return null;
			}
			const socket = await httpConnect(addressType, addressRemote, portRemote, log, parsed, globalThis.connect, rawClientData || new Uint8Array(0));
			return socket;
		}

		case OUTBOUND_VLESS: {
			// vless 出站（UDP 也走这里，UDP 帧由调用方处理首包语义）
			return vlessOutboundConnect(
				{ address: ob.address, port: Number(ob.port), uuid: ob.uuid, path: ob.path, tls: !!ob.tls, sni: ob.sni || '', transport: ob.transport },
				isUDP ? 0x02 : 0x01,
				addressType, addressRemote, portRemote,
				rawClientData || new Uint8Array(0),
				log
			);
		}

		default:
			log(`unknown outbound type: ${ob.type}`);
			return null;
	}
}

/**
 * 获取出站对象（按 name 或默认）
 * @param {Object} config
 * @param {string|null} outboundName 规则指定出站名 / direct / reject
 */
export function resolveOutbound(config, outboundName) {
	if (!outboundName || outboundName === OUTBOUND_DIRECT) return OUTBOUND_DIRECT;
	if (outboundName === OUTBOUND_REJECT) return OUTBOUND_REJECT;
	return config.outboundByName[outboundName] || OUTBOUND_DIRECT;
}
