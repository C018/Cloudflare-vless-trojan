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
 * DoH 解析域名（多源，优先域名型因为 Worker 环境 fetch IP 型可能不可达），
 * rtype='A' 返回首个 A 记录 IPv4，rtype='AAAA' 返回首个 AAAA 记录 IPv6；失败返回 null。
 * 缓存 key 含记录类型，TTL 300s。
 * @param {string} hostname
 * @param {Function} log
 * @param {'A'|'AAAA'} [rtype]
 */
export async function resolveViaDoH(hostname, log, rtype = 'A') {
	const cacheKey = `${rtype}:${hostname}`;
	const hit = dohCache.get(cacheKey);
	if (hit && Date.now() - hit.ts < DOH_CACHE_TTL) {
		// 缓存命中为正常路径高频日志，降噪不打
		return hit.ip;
	}
	// 多源 DoH：按用户偏好 DNS 不用 Cloudflare（移除 cloudflare-dns.com）；
	// Google IP 型优先，国内非 CF 域名型兜底，失败自动切换下一源
	const endpoints = [
		'https://8.8.8.8/resolve',
		'https://8.8.4.4/resolve',
		'https://doh.pub/resolve',
		'https://dns.alidns.com/resolve',
	];
	const wantType = rtype === 'AAAA' ? 28 : 1;
	const ipRe = rtype === 'AAAA' ? /^[0-9a-fA-F:]+$/ : /^\d{1,3}(\.\d{1,3}){3}$/;
	let resolved = null;
	for (const endpoint of endpoints) {
		const ac = new AbortController();
		const timer = setTimeout(() => ac.abort(), 2500);
		try {
			const url = `${endpoint}?name=${encodeURIComponent(hostname)}&type=${rtype}`;
			const resp = await fetch(url, { headers: { accept: 'application/dns-json' }, signal: ac.signal });
			if (resp.ok) {
				const j = await resp.json();
				const ans = Array.isArray(j.Answer) ? j.Answer : [];
				const ip = ans.find((a) => a.type === wantType && ipRe.test(a.data))?.data;
				if (ip) {
					clearTimeout(timer);
					resolved = ip;
					break;
				}
			}
		} catch (e) {
			// try next endpoint
		} finally {
			clearTimeout(timer);
		}
	}
	if (resolved) dohCache.set(cacheKey, { ip: resolved, ts: Date.now() });
	else log(`doh resolve failed: ${hostname} (${rtype})`);
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
export function isCloudflareIp(ip) {
	if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
	const n = ipv4ToInt(ip);
	return CLOUDFLARE_IPV4_RANGES.some(([base, mask]) => (n & mask) === base);
}

/** 已知 Cloudflare 托管域名后缀（DoH 失败时兜底判定，避免 CF 站点退化为 sockets 直连必挂） */
const CLOUDFLARE_DOMAINS = [
	'.cloudflare.com', '.cloudflare.net', '.jsdelivr.net', '.workers.dev',
	'.pages.dev', '.trycloudflare.com', '.cf-ipfs.com', '.cloudflareinsights.com'
];
export function isCloudflareDomain(hostname) {
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

/** 当前 proxyIP 是否处于 down 冷却期（60s 内走直连、不走 proxyip） */
export function isProxyIpDown() {
	return proxyipHealth.state === 'down' && Date.now() - proxyipHealth.downAt < PROXYIP_DOWN_TTL;
}

/**
 * proxyip 出站名模式：返回匹配的出站对象（vless/socks5/http）；未启用出站名模式或出站不存在返回 null
 */
function proxyipOutboundOb(config) {
	if (!config.proxyipOutbound) return null;
	const ob = resolveOutbound(config, config.proxyipOutbound);
	if (!ob || typeof ob === 'string') return null; // direct / reject / 不存在
	if (ob.type !== OUTBOUND_VLESS && ob.type !== OUTBOUND_SOCKS5 && ob.type !== OUTBOUND_HTTP) return null;
	return ob;
}

/**
 * 经 proxyip 出站代理（出站名模式）建连目标端点：替代裸连 proxyipHost:proxyipPort，
 * 用指定出站（vless/socks5/http）连目标 hostname:port 并写入首包
 * @returns {Promise<Object|null>} Socket/流式对象 或 null
 */
async function connectViaProxyOutbound(config, hostname, port, initialData, log) {
	const ob = proxyipOutboundOb(config);
	if (!ob) return null;
	const addressType = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : (hostname.includes(':') ? 3 : 2);
	log(`direct ${hostname}:${port} -> retry via outbound ${ob.name}`);
	const out = await handleTcpOutbound({
		config, outbound: ob, addressType, addressRemote: hostname, portRemote: port,
		rawClientData: initialData || new Uint8Array(0), log, isUDP: false,
	});
	if (!out) return null;
	directRouteMeta.set(out, { usedProxyIp: true });
	return out;
}

/**
 * 强制经 proxyIP 建连（对齐 Vless_workers_pages 的 retry：直连无数据后重连 proxyip:proxyPort 写首包）。
 * 出站名模式：走指定出站代理连目标。
 * @returns {Promise<Object|null>} Socket 或 null
 */
export async function connectViaProxyIp(config, hostname, port, initialData, log) {
	// 出站名模式：无数据回退同样走该出站代理
	const proxyOb = proxyipOutboundOb(config);
	if (proxyOb) {
		const out = await connectViaProxyOutbound(config, hostname, port, initialData, log);
		if (!out) markProxyIpDown(log);
		return out;
	}
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
		// A 记录不存在（纯 IPv6 域名，如 ipv6-api.speedtest.net）→ 查 AAAA，方括号字面量直连 IPv6
		const ip6 = await resolveViaDoH(hostname, log, 'AAAA');
		if (ip6) {
			const ip6Literal = `[${ip6}]`;
			log(`direct ${hostname}:${port} -> doh aaaa fallback ${ip6Literal}:${port}`);
			s = await tryConnect(ip6Literal, port, log);
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
	const proxyipEnabled = (config.proxyipHost || config.proxyipOutbound) && !config.proxyipDisabled;
	const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');

	maybeResetProxyIpHealth(log);
	const proxyipDown = proxyipEnabled && proxyipHealth.state === 'down';

	// 已知 CF 托管域名后缀 → 直接走 proxyip（若启用且未 down）；IP 字面量属于 CF 地址段同理
	const cfDomain = !isIpLiteral && isCloudflareDomain(hostname);
	const cfIpLiteral = isIpLiteral && !hostname.includes(':') && isCloudflareIp(hostname);

	// 未知域名（ip.sb / ip.skk.moe 等开 CF CDN 的站点）：DoH 预解析 IP 落 CF 地址段 → 同样按 CF 站点走 proxyip，
	// 避免 sockets 直连 CF IP 被拦截后只能靠 5s 首包回退（慢且偶发失败）；DoH 结果有 300s 缓存
	let cfResolvedDomain = false;
	if (proxyipEnabled && !proxyipDown && !isIpLiteral && !cfDomain) {
		const ip = await resolveViaDoH(hostname, log);
		if (ip && isCloudflareIp(ip)) {
			cfResolvedDomain = true;
		}
	}

	if (proxyipEnabled && !proxyipDown && (cfDomain || cfIpLiteral || cfResolvedDomain)) {
		// 出站名模式：CF 目标走指定出站代理（vless/socks5/http），失败降级直连
		const proxyOb = proxyipOutboundOb(config);
		if (proxyOb) {
			const out = await connectViaProxyOutbound(config, hostname, port, initialData, log);
			if (out) return out;
			markProxyIpDown(log);
			log(`proxyip outbound ${proxyOb.name} failed; degrade to direct ${hostname}:${port}`);
			return connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain || cfResolvedDomain, initialData, log);
		}
		const proxyHost = config.proxyipHost;
		const proxyPort = Number(config.proxyipPort || 443);
		let socket = await tryConnect(proxyHost, proxyPort, log);
		if (!socket) {
			// proxyip 失败：标记 down 并降级直连目标 hostname/IP
			markProxyIpDown(log);
			log(`proxyip ${proxyHost}:${proxyPort} connect failed; degrade to direct ${hostname}:${port}`);
			return connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain || cfResolvedDomain, initialData, log);
		}
		const out = await writeInitial(socket, initialData, log);
		if (out) directRouteMeta.set(out, { usedProxyIp: true });
		return out;
	}

	// 直连路径（非 CF 目标 / proxyip 未启用 / proxyip down 降级）
	return connectDirectWithMeta(config, hostname, port, isIpLiteral, cfDomain || cfResolvedDomain, initialData, log);
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
