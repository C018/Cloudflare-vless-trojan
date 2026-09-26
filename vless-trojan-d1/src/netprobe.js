/**
 * Network probing: latency / connectivity test through project outbound chain
 * 网络状态检测与连通性测试：按项目网络设置（decideRoute 分流 + default_outbound + proxyip 替换 + socks5/http/vless 出站隧道）
 * 建立 TCP 连接并对目标发起明文 HTTP 探测，读取响应头得到延迟序列。
 * 说明：Workers 平台无法对 Socket 做 TLS 客户端握手，探测走 80 端口明文 HTTP（隧道模式下远端 80 的 HTTP 服务会返回 301/200/400 等响应头，足以判定连通与延迟）；
 *       proxyip（443）收到明文 HTTP 会返回 400 响应头，同样可用于 proxyip 可用性判定。
 */

import { decideRoute } from './routing/engine.js';
import { handleTcpOutbound, resolveOutbound, isCloudflareIp, isCloudflareDomain, isProxyIpDown } from './outbound/tcp.js';
import { vlessOutboundConnect } from './outbound/vless.js';
import { wrapUdpFrame, readUdpFrames } from './outbound/udp.js';

// ---- 常量 ----
// 网络状态检测目标：name 展示名 / host 探测主机 / port 探测端口 / region cn=国内 intl=国际 / icon 图标
export const NETSTAT_TARGETS = [
	{ name: '字节跳动', host: 'www.bytedance.com', port: 80, region: 'cn', icon: '🎵', color: '#325AB4' },
	{ name: 'Bilibili', host: 'www.bilibili.com', port: 80, region: 'cn', icon: '📺', color: '#FB7299' },
	{ name: '微信', host: 'weixin.qq.com', port: 80, region: 'cn', icon: '💬', color: '#07C160' },
	{ name: '淘宝', host: 'www.taobao.com', port: 80, region: 'cn', icon: '🛒', color: '#FF5000' },
	{ name: 'GitHub', host: 'github.com', port: 80, region: 'intl', icon: '🐙', color: '#24292F' },
	{ name: 'jsDelivr', host: 'cdn.jsdelivr.net', port: 80, region: 'intl', icon: '📦', color: '#E84D0E' },
	{ name: 'Cloudflare', host: 'www.cloudflare.com', port: 80, region: 'intl', icon: '☁️', color: '#F6821F' },
	{ name: 'Google', host: 'www.google.com', port: 80, region: 'intl', icon: '🔍', color: '#4285F4' },
	{ name: 'YouTube', host: 'www.youtube.com', port: 80, region: 'intl', icon: '▶️', color: '#FF0000' },
];
// 每个目标采样次数（卡片一行 16 个圆点）
export const NETSTAT_SAMPLES = 16;
// 单次探测超时（ms）
export const PROBE_TIMEOUT = 3000;
// 目标内采样并发批大小
const NETSTAT_BATCH = 4;
// proxyip 测试采样次数
export const PROXYIP_SAMPLES = 3;
// UDP 测试超时（ms）
export const UDP_TEST_TIMEOUT = 5000;
// 出站测试单次超时（ms）
export const OUTBOUND_TEST_TIMEOUT = 5000;

/**
 * 构造明文 HTTP 探测请求
 * @param {string} hostname
 * @param {number} port
 * @param {string} path
 * @returns {Uint8Array}
 */
function makeProbeRequest(hostname, port, path = '/') {
	return new TextEncoder().encode(
		`GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nUser-Agent: Mozilla/5.0 (netprobe)\r\nConnection: close\r\n\r\n`
	);
}

/**
 * 字节数组合并
 */
function concatBytes(a, b) {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/**
 * 在字节流中查找 HTTP 头结束符 \r\n\r\n
 * @returns {number} 结束位置下标，未找到返回 -1
 */
function findHeaderEnd(buf) {
	for (let i = 0; i < buf.length - 3; i++) {
		if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
			return i + 4;
		}
	}
	return -1;
}

/**
 * 关闭探测连接（兼容 Socket 与 vless 流式对象）
 */
function closeRemote(remote) {
	try {
		if (typeof remote.close === 'function') {
			remote.close();
		} else if (remote.writable && typeof remote.writable.close === 'function') {
			remote.writable.close().catch(() => { /* ignore */ });
		}
	} catch (e) { /* ignore */ }
}

/**
 * 读取远端流直到收到 HTTP 响应头或超时
 * @param {Object} remote {readable, writable, close?}
 * @param {number} timeoutMs
 * @returns {Promise<number|null>} 收到响应头的时间戳（Date.now），超时/失败返回 null
 */
function readUntilHeader(remote, timeoutMs) {
	return new Promise((resolve) => {
		let buf = new Uint8Array(0);
		let settled = false;
		const finish = (val) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(val);
		};
		const timer = setTimeout(() => finish(null), timeoutMs);
		(async () => {
			const reader = remote.readable.getReader();
			try {
				while (!settled) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					buf = concatBytes(buf, value);
					if (findHeaderEnd(buf) >= 0) {
						finish(Date.now());
						break;
					}
					if (buf.length > 65536) {
						finish(null);
						break;
					}
				}
			} catch (e) { /* 连接被关闭 */ }
			finish(null);
			try { reader.releaseLock(); } catch (e) { /* ignore */ }
		})();
	});
}

/**
 * 单次探测：按项目网络设置（decideRoute + 出站 + proxyip 替换）建立 TCP 隧道并发 HTTP 请求
 * @param {Object} config 请求级配置
 * @param {string} hostname 目标域名
 * @param {number} port 目标端口
 * @param {Uint8Array} requestData 探测请求数据
 * @param {Function} log
 * @returns {Promise<number|null>} 延迟 ms（收到响应头），失败返回 null
 */
async function probeOnce(config, hostname, port, requestData, log) {
	const t0 = Date.now();
	let remote;
	try {
		const route = await decideRoute(config, 2, hostname);
		const outbound = resolveOutbound(config, route.outbound);
		remote = await handleTcpOutbound({
			config, outbound, addressType: 2, addressRemote: hostname,
			portRemote: port, rawClientData: requestData, log
		});
	} catch (e) {
		return null;
	}
	if (!remote) return null;
	const end = await readUntilHeader(remote, PROBE_TIMEOUT);
	closeRemote(remote);
	if (end === null) return null;
	return end - t0;
}

/**
 * 对单个目标采样多次得到延迟序列
 * @returns {Promise<Object>} {name, host, port, region, icon, samples, latency, success, total}
 */
async function probeTarget(config, target, log) {
	const samples = [];
	for (let i = 0; i < NETSTAT_SAMPLES; i += NETSTAT_BATCH) {
		const batch = [];
		const end = Math.min(i + NETSTAT_BATCH, NETSTAT_SAMPLES);
		for (let j = i; j < end; j++) {
			batch.push(probeOnce(config, target.host, target.port, makeProbeRequest(target.host, target.port), log));
		}
		const times = await Promise.all(batch);
		for (const t of times) samples.push(t);
	}
	const ok = samples.filter((v) => v !== null);
	const latency = ok.length > 0 ? Math.round(ok.reduce((a, b) => a + b, 0) / ok.length) : null;
	const min = ok.length > 0 ? Math.min(...ok) : null;
	const max = ok.length > 0 ? Math.max(...ok) : null;
	const loss = samples.length > 0 ? Math.round(((samples.length - ok.length) / samples.length) * 100) : 100;
	return { ...target, samples, latency, min, max, loss, success: ok.length, total: samples.length };
}

/**
 * 网络状态检测入口：对全部目标并行采样
 * @returns {Promise<{ok:boolean, ts:number, targets:Array<Object>}>}
 */
export async function runNetstatusTest(config, log) {
	const settled = await Promise.allSettled(NETSTAT_TARGETS.map((t) => probeTarget(config, t, log)));
	return {
		ok: true,
		ts: Date.now(),
		targets: settled.map((r, i) => r.status === 'fulfilled'
			? r.value
			: { ...NETSTAT_TARGETS[i], samples: [], latency: null, success: 0, total: 0, error: (r.reason && r.reason.message) || 'error' })
	};
}

/**
 * 路由测试：按真实转发判定逻辑（decideRoute 分流 + resolveOutbound 回退 + directConnect 的
 * proxyip 替换规则）返回目标域名在当前配置下的实际路由走向。
 * 与代理会话 handleTcpOutbound 走同一套判定：命中分流规则 → 出站名；未命中 → 默认出站；
 * direct 路径下仅当 proxyip 启用（默认出站为 direct）且目标为 Cloudflare 站点且未 down 时走 proxyip。
 * @param {Object} config 请求级配置
 * @param {string} domain 目标域名或 IP（如 www.google.com / 1.1.1.1 / 2606:4700::1111）
 * @returns {Promise<{ok:boolean, domain:string, route:string, name:string, reason:string, rule?:string|null}>}
 */
export async function testRoute(config, domain, log) {
	const host = String(domain || '').trim().toLowerCase();
	if (!host) return { ok: false, error: 'domain required' };

	// 地址类型与 proxy-session 一致：1=IPv4 2=Domain 3=IPv6
	let addressType = 2;
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) addressType = 1;
	else if (host.includes(':')) addressType = 3;
	const isIpLiteral = addressType !== 2;

	const decision = await decideRoute(config, addressType, host);
	const ruleHit = !!decision.rule;
	const rulePrefix = ruleHit ? `分流规则 ${decision.rule.rule} → ` : '';

	// 与 handleTcpOutbound 一致：先 resolveOutbound（未知出站名回退 direct）
	const outbound = resolveOutbound(config, decision.outbound);

	if (outbound === 'reject') {
		return { ok: true, domain: host, route: 'reject', name: 'reject',
			reason: ruleHit ? `${rulePrefix}reject（拒绝连接）` : '默认出站 reject（拒绝连接）',
			rule: ruleHit ? decision.rule.rule : null };
	}

	if (outbound === 'direct') {
		// 出站名不存在时 resolveOutbound 回退 direct：保留原始名字用于提示
		const originalName = decision.outbound;
		// 与 directConnect 判定完全一致（proxyip 支持端点或出站名两种模式）
		const proxyipEnabled = (!!config.proxyipHost || !!config.proxyipOutbound) && !config.proxyipDisabled;
		const proxyipDown = proxyipEnabled && isProxyIpDown();
		const cfDomain = !isIpLiteral && isCloudflareDomain(host);
		const cfIpLiteral = isIpLiteral && !host.includes(':') && isCloudflareIp(host);
		if (proxyipEnabled && !proxyipDown && (cfDomain || cfIpLiteral)) {
			if (config.proxyipOutbound) {
				return { ok: true, domain: host, route: 'proxyip', name: `outbound:${config.proxyipOutbound}`,
					reason: `${rulePrefix}Cloudflare 站点（已知 CF 后缀/IP 段）→ 使用出站代理 ${config.proxyipOutbound} 出站`,
					rule: ruleHit ? decision.rule.rule : null };
			}
			const ep = `${config.proxyipHost}:${Number(config.proxyipPort || 443)}`;
			return { ok: true, domain: host, route: 'proxyip', name: ep,
				reason: `${rulePrefix}Cloudflare 站点（已知 CF 后缀/IP 段）→ proxyip ${ep}`,
				rule: ruleHit ? decision.rule.rule : null };
		}
		if (ruleHit) {
			return { ok: true, domain: host, route: 'direct', name: 'direct',
				reason: `${rulePrefix}direct`, rule: decision.rule.rule };
		}
		if (originalName && originalName !== 'direct' && originalName !== 'reject') {
			return { ok: true, domain: host, route: 'direct', name: 'direct',
				reason: `默认出站 ${originalName} 不存在，回退 direct`, rule: null };
		}
		return { ok: true, domain: host, route: 'direct', name: 'direct',
			reason: '默认出站 direct', rule: null };
	}

	// 命中出站代理（socks5 / http / vless）：resolveOutbound 返回出站对象，取显示名
	const outboundName = typeof outbound === 'string' ? outbound : outbound.name;
	return { ok: true, domain: host, route: 'outbound', name: outboundName,
		reason: ruleHit ? `${rulePrefix}出站 ${outboundName}` : `默认出站 ${outboundName}`,
		rule: ruleHit ? decision.rule.rule : null };
}

/**
 * proxyip 测试：支持两种模式——
 * 1) 出站名模式（proxyip 填出站名）：走指定出站代理（vless/socks5/http）连目标发 HTTP 探测；
 * 2) 端点模式：按项目 proxyip 逻辑连接 proxyipHost:proxyipPort 裸 TCP，发 HTTP 请求到 Cloudflare 相关站点。
 * @returns {Promise<{ok:boolean, latency?:number, endpoint?:string, mode?:string, outbound?:string, error?:string}>}
 */
export async function testProxyIp(config, log) {
	const host = 'www.cloudflare.com';
	const probePort = 443;
	// 出站名模式：走指定出站代理探测
	if (config.proxyipOutbound) {
		const ob = resolveOutbound(config, config.proxyipOutbound);
		if (!ob || typeof ob === 'string') {
			return { ok: false, mode: 'outbound', error: `出站 ${config.proxyipOutbound} 不存在，请检查出站配置` };
		}
		const t0 = Date.now();
		let remote = null;
		try {
			remote = await handleTcpOutbound({
				config, outbound: ob, addressType: 2, addressRemote: host,
				portRemote: probePort, rawClientData: makeProbeRequest(host, probePort), log, isUDP: false,
			});
		} catch (e) {
			return { ok: false, mode: 'outbound', outbound: config.proxyipOutbound, error: `出站连接失败: ${e.message}` };
		}
		if (!remote) {
			return { ok: false, mode: 'outbound', outbound: config.proxyipOutbound, error: '出站连接失败或无响应' };
		}
		const end = await readUntilHeader(remote, PROBE_TIMEOUT);
		closeRemote(remote);
		if (end === null) {
			return { ok: false, mode: 'outbound', outbound: config.proxyipOutbound, error: '连接超时或无响应' };
		}
		return { ok: true, latency: end - t0, mode: 'outbound', outbound: config.proxyipOutbound };
	}
	if (!config.proxyipHost) {
		return { ok: false, error: '未配置 proxyip，请先在系统设置中填写' };
	}
	const t0 = Date.now();
	let socket = null;
	try {
		socket = globalThis.connect ? globalThis.connect({ hostname: config.proxyipHost, port: Number(config.proxyipPort || 443) }) : null;
		if (!socket) return { ok: false, error: 'connect 不可用' };
		const writer = socket.writable.getWriter();
		await writer.write(makeProbeRequest(host, probePort));
		writer.releaseLock();
	} catch (e) {
		try { if (socket) socket.close(); } catch (x) { /* ignore */ }
		return { ok: false, error: `连接失败: ${e.message}` };
	}
	const end = await readUntilHeader(socket, PROBE_TIMEOUT);
	try { socket.close(); } catch (e) { /* ignore */ }
	if (end === null) {
		return { ok: false, error: '连接超时或无响应' };
	}
	return { ok: true, latency: end - t0, mode: 'proxyip', endpoint: `${config.proxyipHost}:${config.proxyipPort || 443}` };
}

/**
 * 构造标准 DNS 查询报文（A 记录）
 * @param {string} domain
 * @returns {Uint8Array}
 */
function buildDnsQuery(domain) {
	const id = 0x1234;
	const parts = [id >> 8, id & 0xff];
	parts.push(0x01, 0x00); // flags: RD
	parts.push(0x00, 0x01); // QDCOUNT
	parts.push(0x00, 0x00, 0x00, 0x00, 0x00, 0x00); // AN/NS/ARCOUNT
	for (const label of String(domain).split('.')) {
		parts.push(label.length);
		for (let i = 0; i < label.length; i++) parts.push(label.charCodeAt(i));
	}
	parts.push(0x00);
	parts.push(0x00, 0x01); // QTYPE A
	parts.push(0x00, 0x01); // QCLASS IN
	return new Uint8Array(parts);
}

/**
 * UDP 测试：按 udp_outbound 配置的 vless 出站发 VLESS_CMD_UDP 帧做 DNS 查询（8.8.8.8:53 查 example.com）
 * @returns {Promise<{ok:boolean, latency?:number, bytes?:number, error?:string}>}
 */
export async function testUdp(config, log) {
	let vlessOb = null;
	const udpName = (config.udpOutbound || '').trim();
	if (udpName) {
		const ob = config.outboundByName[udpName];
		if (ob && ob.type === 'vless') {
			vlessOb = ob;
		} else {
			return { ok: false, error: `UDP 出站 '${udpName}' 不存在或非 vless（仅 vless 支持 UDP）` };
		}
	} else {
		vlessOb = config.outbounds.find((o) => o.type === 'vless');
		if (!vlessOb) {
			return { ok: false, error: '未配置 vless 出站，无法测试 UDP' };
		}
	}
	const dnsQuery = buildDnsQuery('example.com');
	const frame = wrapUdpFrame(dnsQuery);
	const t0 = Date.now();
	let conn;
	try {
		conn = await vlessOutboundConnect(
			{ address: vlessOb.address, port: Number(vlessOb.port), uuid: vlessOb.uuid, path: vlessOb.path, tls: !!vlessOb.tls, sni: vlessOb.sni || '', transport: vlessOb.transport },
			0x02, 1, '8.8.8.8', 53, frame, log
		);
	} catch (e) {
		return { ok: false, error: `UDP 出站连接失败: ${e.message}` };
	}
	if (!conn) {
		return { ok: false, error: 'UDP 出站连接失败' };
	}
	const result = await new Promise((resolve) => {
		let timer = setTimeout(() => resolve({ ok: false, error: 'UDP 响应超时' }), UDP_TEST_TIMEOUT);
		readUdpFrames(conn.readable, (payload) => {
			// DNS 响应判定：ID 匹配 0x1234 且 QR=1
			if (payload.length >= 12 && payload[0] === 0x12 && payload[1] === 0x34 && (payload[2] & 0x80) !== 0) {
				clearTimeout(timer);
				resolve({ ok: true, latency: Date.now() - t0, bytes: payload.length });
			}
		}, log);
	});
	try { conn.writable.close().catch(() => { /* ignore */ }); } catch (e) { /* ignore */ }
	return result;
}

/**
 * 出站代理测试：对该出站建立隧道并发 HTTP 探测（www.gstatic.com/generate_204）
 * @param {Object} config
 * @param {Object} outbound 出站记录（socks5/http/vless）
 * @returns {Promise<{ok:boolean, latency?:number, error?:string}>}
 */
export async function testOutbound(config, outbound, log) {
	const target = 'www.gstatic.com';
	const port = 80;
	const t0 = Date.now();
	let remote;
	try {
		remote = await handleTcpOutbound({
			config, outbound, addressType: 2, addressRemote: target,
			portRemote: port, rawClientData: makeProbeRequest(target, port, '/generate_204'), log
		});
	} catch (e) {
		return { ok: false, error: e.message };
	}
	if (!remote) {
		return { ok: false, error: '隧道建立失败' };
	}
	const end = await readUntilHeader(remote, OUTBOUND_TEST_TIMEOUT);
	closeRemote(remote);
	if (end === null) {
		return { ok: false, error: '连接超时或无响应' };
	}
	return { ok: true, latency: end - t0 };
}
