/**
 * TCP outbound dispatcher
 * 按分流选出的出站建立 TCP 隧道；vless 出站返回流式对象，其余返回 Socket
 */

import { vlessOutboundConnect } from './vless.js';
import { socks5Connect, parseSocks5Address } from './socks5.js';
import { httpConnect, parseHttpAddress } from './http.js';
import { OUTBOUND_DIRECT, OUTBOUND_REJECT, OUTBOUND_SOCKS5, OUTBOUND_HTTP, OUTBOUND_VLESS } from '../config/constants.js';

/** DoH 解析结果缓存（TTL 300s，避免每个新连接都重复 DoH 查询拖慢建连） */
const DOH_CACHE_TTL = 300_000;
const dohCache = new Map(); // hostname -> { ip, ts }

/**
 * DoH 解析域名（Google Public DNS，IP 直连形式，避免 DoH 域名本身解析不到），返回首个 A 记录 IPv4；失败返回 null（交由运行时 DNS 兜底）
 * @param {string} hostname
 * @param {Function} log
 */
async function resolveViaDoH(hostname, log) {
	const hit = dohCache.get(hostname);
	if (hit && Date.now() - hit.ts < DOH_CACHE_TTL) {
		log(`doh cache ${hostname} -> ${hit.ip}`);
		return hit.ip;
	}
	// 仅用 Google，且 https://IP 形式（8.8.8.8 / 8.8.4.4 证书含 IP SAN，可直连 TLS）
	const endpoints = ['https://8.8.8.8/resolve', 'https://8.8.4.4/resolve'];
	let resolved = null;
	for (const endpoint of endpoints) {
		const ac = new AbortController();
		const timer = setTimeout(() => ac.abort(), 3000);
		try {
			const url = `${endpoint}?name=${encodeURIComponent(hostname)}&type=A`;
			const resp = await fetch(url, { headers: { accept: 'application/dns-json' }, signal: ac.signal });
			if (resp.ok) {
				const j = await resp.json();
				const ans = Array.isArray(j.Answer) ? j.Answer : [];
				const ip = ans.find((a) => a.type === 1 && /^\d{1,3}(\.\d{1,3}){3}$/.test(a.data))?.data;
				if (ip) {
					clearTimeout(timer);
					resolved = ip;
					log(`doh resolved ${hostname} -> ${ip}`);
					break;
				}
			}
		} catch (e) {
			// try next endpoint
		} finally {
			clearTimeout(timer);
		}
	}
	if (resolved) dohCache.set(hostname, { ip: resolved, ts: Date.now() });
	else log(`doh resolve failed: ${hostname}`);
	return resolved;
}

/** Cloudflare 官方 IPv4 地址段（https://www.cloudflare.com/ips-v4） */
const CLOUDFLARE_IPV4_RANGES = [
	'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
	'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
	'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
	'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '1.0.0.0/24', '1.1.1.0/24'
].map((cidr) => {
	const [ip, prefix] = cidr.split('/');
	const p = Number(prefix);
	const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
	const parts = ip.split('.');
	const base = ((((+parts[0]) << 24) + ((+parts[1]) << 16) + ((+parts[2]) << 8) + (+parts[3])) >>> 0) & mask;
	return [base, mask];
});

/** IPv4 字符串转 uint32 */
function ipv4ToInt(ip) {
	const parts = ip.split('.');
	return ((((+parts[0]) << 24) + ((+parts[1]) << 16) + ((+parts[2]) << 8) + (+parts[3])) >>> 0);
}

/** 判断 IPv4 是否属于 Cloudflare 地址段（即目标为 CF 托管/开启 Cloudflare 的站点） */
function isCloudflareIp(ip) {
	if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
	const n = ipv4ToInt(ip);
	return CLOUDFLARE_IPV4_RANGES.some(([base, mask]) => (n & mask) === base);
}

/** 已知 Cloudflare 托管域名后缀（DoH 失败时兜底判定，避免 CF 站点退化为 sockets 直连必挂） */
const CLOUDFLARE_DOMAINS = [
	'.cloudflare.com', '.cloudflare.net', '.jsdelivr.net', '.workers.dev',
	'.pages.dev', '.trycloudflare.com', '.cf-ipfs.com', '.cloudflareinsights.com'
];
function isCloudflareDomain(hostname) {
	const h = hostname.toLowerCase();
	return CLOUDFLARE_DOMAINS.some((s) => h === s.slice(1) || h.endsWith(s));
}

/** proxyIP 健康状态：connect 失败或首包无响应标记 down，60s 内降级直连，60s 后重置 unknown 再试 */
const PROXYIP_DOWN_TTL = 60_000;
let proxyipHealth = { state: 'unknown', downAt: 0 }; // state: 'unknown' | 'down'

/** 记录 direct 出站路由元信息（是否实际走了 proxyip），供上层做"无数据回退 proxyip"判定 */
export const directRouteMeta = new WeakMap();

/** 标记 proxyIP 为 down（60s 冷却期内走直连），供上层在 proxyIP 无首包响应时调用 */
export function markProxyIpDown(log) {
	if (proxyipHealth.state !== 'down') {
		proxyipHealth.state = 'down';
		proxyipHealth.downAt = Date.now();
		log('proxyip marked down (no response), degrade to direct for 60s');
	}
}

/** 重置 proxyIP 健康状态为 unknown（60s 冷却期满后自动调用） */
function maybeResetProxyIpHealth(log) {
	if (proxyipHealth.state === 'down' && Date.now() - proxyipHealth.downAt >= PROXYIP_DOWN_TTL) {
		proxyipHealth.state = 'unknown';
		log('proxyip health reset to unknown, will retry proxyip');
	}
}

/**
 * 强制经 proxyIP 建连（对齐 Vless_workers_pages 的 retry：直连无数据后重连 proxyip:proxyPort 写首包）
 * @returns {Promise<Object|null>} Socket 或 null
 */
export async function connectViaProxyIp(config, hostname, port, initialData, log) {
	const proxyHost = config.proxyipHost;
	const proxyPort = Number(config.proxyipPort || 443);
	if (!proxyHost) return null;
	log(`direct ${hostname}:${port} -> retry via proxyip ${proxyHost}:${proxyPort}`);
	const socket = await tryConnect(proxyHost, proxyPort, log);
	if (!socket) {
		markProxyIpDown(log);
		return null;
	}
	const out = await writeInitial(socket, initialData, log);
	if (!out) {
		markProxyIpDown(log);
		return null;
	}
	directRouteMeta.set(out, { usedProxyIp: true });
	return out;
}

/**
 * 直连目标端点（重试入口）：保持直连语义，返回 socket 并记录 usedProxyIp=false
 */
async function connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain, initialData, log) {
	const socket = await connectDirect(hostname, port, isIpLiteral, cfDomain, log);
	if (!socket) {
		log(`connect unavailable (${hostname}:${port})`);
		return null;
	}
	const out = await writeInitial(socket, initialData, log);
	if (out) directRouteMeta.set(out, { usedProxyIp: false });
	return out;
}

/** 统一 connect：兼容同步 Socket 与 Promise，失败返回 null */
async function tryConnect(host, port, log) {
	let s;
	try {
		s = globalThis.connect ? globalThis.connect({ hostname: host, port }) : undefined;
		if (s && typeof s.then === 'function') s = await s;
	} catch (e) {
		log(`direct connect error: ${e.message}`);
		return null;
	}
	return s || null;
}

/** 直连目标端点（不经 proxyip）：非 IP 且非已知 CF 域名 → 原生 DNS 直连优先，失败才 DoH 回退 */
async function connectDirect(hostname, port, isIpLiteral, cfDomain, log) {
	if (!isIpLiteral && !cfDomain) {
		// 原生 DNS 直连优先：直接用 hostname 建连，交给 CF 运行时 DNS，省去 DoH 预解析延迟
		log(`direct ${hostname}:${port} -> native dns ${hostname}:${port}`);
		let s = await tryConnect(hostname, port, log);
		if (s) return s;
		// 原生 DNS 失败（抛错/返回 null）才回退 DoH 解析出 IP 再连一次
		const ip = await resolveViaDoH(hostname, log);
		if (ip) {
			log(`direct ${hostname}:${port} -> doh fallback ${ip}:${port}`);
			s = await tryConnect(ip, port, log);
			if (s) return s;
		}
		return null;
	}
	// IP 字面量 / 已知 CF 域名（proxyip down 降级时也走到这里）：直接用 hostname/IP 建连
	return tryConnect(hostname, port, log);
}

/** 在返回前写入首包并释放锁（避免调用方 getWriter 报 WritableStream locked） */
async function writeInitial(socket, initialData, log) {
	if (initialData && initialData.length > 0) {
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
 * 直连：默认直连目标端点；仅当默认出站为 direct（config.proxyipDisabled=false）且
 * 目标为 Cloudflare 站点（已知 CF 后缀域名 或 IP 字面量属于 CF 地址段）时，端点替换为
 * proxyip:port 建立裸 TCP 连接（原生 cloudflare:sockets 无法访问 Cloudflare 及开启了
 * Cloudflare 的站点，需走 proxyIP）。非 CF 目标一律 sockets 直连。
 * 直连优先"原生 DNS"（直接用 hostname 建连，交给 CF 运行时 DNS），失败才 DoH 解析出 IP 再连一次；
 * 已知 CF 后缀域名无需 DoH 直接走 proxyIP（若启用）。
 * proxyIP 健康缓存：走 proxyip connect 失败标记 down 并记录时间，down 状态 60s 内直接降级直连，
 * 60s 后重置 unknown 再试，降级与恢复均打日志。
 * @param {Object} config
 * @param {string} hostname
 * @param {number} port
 * @param {Uint8Array} initialData
 */
async function directConnect(config, hostname, port, initialData, log) {
	// proxyip 仅默认出站为 direct 时启用（config.proxyipDisabled 已编码该条件）；
	// 是否替换端点由"目标是否为 Cloudflare 站点"决定，与端口无关
	const proxyipEnabled = config.proxyipHost && !config.proxyipDisabled;
	const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');

	maybeResetProxyIpHealth(log);
	const proxyipDown = proxyipEnabled && proxyipHealth.state === 'down';

	// 已知 CF 托管域名后缀 → 直接走 proxyip（若启用且未 down）；IP 字面量属于 CF 地址段同理
	const cfDomain = !isIpLiteral && isCloudflareDomain(hostname);
	const cfIpLiteral = isIpLiteral && !hostname.includes(':') && isCloudflareIp(hostname);

	if (proxyipEnabled && !proxyipDown && (cfDomain || cfIpLiteral)) {
		const proxyHost = config.proxyipHost;
		const proxyPort = Number(config.proxyipPort || 443);
		log(`direct ${hostname}:${port} -> proxyip ${proxyHost}:${proxyPort}`);
		let socket = await tryConnect(proxyHost, proxyPort, log);
		if (!socket) {
			// proxyip 失败：标记 down 并降级直连目标 hostname/IP
			markProxyIpDown(log);
			log(`proxyip ${proxyHost}:${proxyPort} connect failed; degrade to direct ${hostname}:${port}`);
			return connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain, initialData, log);
		}
		const out = await writeInitial(socket, initialData, log);
		if (out) directRouteMeta.set(out, { usedProxyIp: true });
		return out;
	}

	// 直连路径（非 CF 目标 / proxyip 未启用 / proxyip down 降级）
	return connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain, initialData, log);
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
