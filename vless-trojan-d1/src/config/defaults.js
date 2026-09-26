/**
 * Defaults + request-scoped config loader (D1 backed)
 */

import { DEFAULT_WS_PATH, OUTBOUND_DIRECT, OUTBOUND_REJECT, INBOUND_TRANSPORT_DEFAULT } from './constants.js';
import { hashPassword } from '../admin/auth.js';

/**
 * 进程级 D1 配置缓存：TTL 30s + pending Promise 防击穿。
 * 消除每个新连接建连路径上的 D1 查询延迟；后台写接口成功后主动失效（见 api.js）。
 */
const CONFIG_CACHE_TTL = 30_000;
const configCache = {
	settings: { p: null, ts: 0 },
	vlessUsers: { p: null, ts: 0 },
	trojanUsers: { p: null, ts: 0 },
	outbounds: { p: null, ts: 0 },
	routingRules: { p: null, ts: 0 },
};

/** 带缓存的加载：TTL 内命中直接复用；未命中时并发请求共享同一个 pending Promise 防止击穿 */
function cachedLoad(key, loader) {
	const e = configCache[key];
	const now = Date.now();
	if (e.p && now - e.ts < CONFIG_CACHE_TTL) return e.p;
	const p = Promise.resolve().then(loader).catch(() => null);
	e.p = p;
	e.ts = now;
	return p;
}

/** 后台写接口成功后主动失效对应缓存，避免改动 30s 内不生效 */
export function invalidateConfigCache(kind) {
	if (kind === 'all') {
		for (const k of Object.keys(configCache)) { configCache[k].p = null; configCache[k].ts = 0; }
		return;
	}
	const e = configCache[kind];
	if (e) { e.p = null; e.ts = 0; }
}

/**
 * 从 D1 读取 settings 表为 map
 * @param {import('@cloudflare/workers-types').D1Database} db
 * @returns {Promise<Object<string,string>>}
 */
export async function loadSettings(db) {
	try {
		const { results } = await db.prepare('SELECT key, value FROM settings').all();
		const map = {};
		for (const row of results || []) map[row.key] = row.value;
		return map;
	} catch (e) {
		return {};
	}
}

/**
 * 读取启用的 vless 用户
 * @returns {Promise<Array<{id:number,uuid:string,remark:string,up:number,down:number,path:string,expire_at:number,traffic_limit:number,traffic_reset_at:number}>>}
 */
export async function loadVlessUsers(db) {
	try {
		const { results } = await db.prepare(
			'SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id'
		).all();
		return results || [];
	} catch (e) {
		// 旧库缺少新列：回退旧查询（后台 API 会自动迁移补列），保证入站不中断
		try {
			const { results } = await db.prepare(
				'SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id'
			).all();
			return (results || []).map((u) => ({ path: '', expire_at: 0, traffic_limit: 0, traffic_reset_at: 0, ...u }));
		} catch (e2) {
			return [];
		}
	}
}

/**
 * 读取启用的 trojan 用户
 */
export async function loadTrojanUsers(db) {
	try {
		const { results } = await db.prepare(
			'SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id'
		).all();
		return results || [];
	} catch (e) {
		try {
			const { results } = await db.prepare(
				'SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id'
			).all();
			return (results || []).map((u) => ({ path: '', expire_at: 0, traffic_limit: 0, traffic_reset_at: 0, ...u }));
		} catch (e2) {
			return [];
		}
	}
}

/** 规范化入站路径：确保以 / 开头、去尾部斜杠 */
export function normalizeInboundPath(p) {
	let s = String(p || '').trim();
	if (!s) return '';
	if (!s.startsWith('/')) s = '/' + s;
	while (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
	return s;
}

/**
 * 到期流量重置：traffic_reset_at 到期的用户清零 up/down 并清空重置时间（一次性重置）
 * @returns {Promise<void>}
 */
async function resetExpiredTraffic(DB, users, table) {
	const now = Math.floor(Date.now() / 1000);
	for (const u of users) {
		if (u.traffic_reset_at > 0 && u.traffic_reset_at <= now) {
			try {
				await DB.prepare(`UPDATE ${table} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(u.id).run();
				u.up = 0;
				u.down = 0;
				u.traffic_reset_at = 0;
			} catch (e) { /* ignore */ }
		}
	}
}

/**
 * 构建入站路径 → 允许的凭据作用域映射。
 * 每个路径同时注册 {path}（ws/h2）与 {path}/Tun（grpc）。
 * 全局路径作用域为 all；用户自定义路径作用域限定为该用户凭据。
 * @param {string} wsPath 全局入站路径
 * @param {Array} vlessUsers
 * @param {Array} trojanUsers
 * @returns {Map<string, Array<{kind:string, credential?:string}>>}
 */
export function buildInboundPathMap(wsPath, vlessUsers, trojanUsers) {
	const map = new Map();
	const register = (rawPath, scope) => {
		const p = normalizeInboundPath(rawPath);
		if (!p) return;
		if (!map.has(p)) map.set(p, []);
		map.get(p).push(scope);
		const tun = `${p}/Tun`;
		if (!map.has(tun)) map.set(tun, []);
		map.get(tun).push(scope);
	};
	register(wsPath, { kind: 'all' });
	for (const u of vlessUsers) if (u.path) register(u.path, { kind: 'vless', credential: u.uuid.toLowerCase() });
	for (const u of trojanUsers) if (u.path) register(u.path, { kind: 'trojan', credential: u.password });
	return map;
}

/**
 * 读取启用出站
 */
export async function loadOutbounds(db) {
	try {
		const { results } = await db.prepare(
			'SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC'
		).all();
		return results || [];
	} catch (e) {
		return [];
	}
}

/**
 * 读取启用分流规则
 */
export async function loadRoutingRules(db) {
	try {
		const { results } = await db.prepare(
			'SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC'
		).all();
		return results || [];
	} catch (e) {
		return [];
	}
}

/**
 * 确保 settings 中存在 admin_password_hash；不存在则生成随机初始密码并落库
 * @param {import('@cloudflare/workers-types').D1Database} db
 * @returns {Promise<{hash:string, tempPassword:string|null}>}
 */
export async function ensureAdminPassword(db) {
	try {
		const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('admin_password_hash').first();
		if (row && row.value) return { hash: row.value, tempPassword: null };
	} catch (e) { /* fallthrough */ }
	const tempPassword = randomUUID().replace(/-/g, '').slice(0, 12);
	const hash = await hashPassword(tempPassword);
	try {
		await db.prepare(
			'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
		).bind('admin_password_hash', hash, Date.now()).run();
		invalidateConfigCache('settings');
	} catch (e) { /* ignore */ }
	return { hash, tempPassword };
}

/**
 * 解析入口列表：优先 entry_list（JSON 数组，支持多入口 + 备注 + 每入口协议），
 * 兼容旧单入口字段（entry_host / entry_port / entry_sni / entry_ws_host）。
 * @param {Object} settings
 * @returns {Array<{host:string,port:string,sni:string,wsHost:string,remark:string,transports:string[]}>}
 */
export function parseEntries(settings) {
	let list = [];
	try {
		const raw = settings.entry_list;
		if (raw) {
			const arr = JSON.parse(raw);
			if (Array.isArray(arr)) list = arr;
		}
	} catch (e) { list = []; }
	if (!list.length && (settings.entry_host || '').trim()) {
		list = [{
			host: settings.entry_host,
			port: settings.entry_port || '',
			sni: settings.entry_sni || '',
			wsHost: settings.entry_ws_host || '',
			remark: '',
			transports: [],
		}];
	}
	return list.map((e) => {
		const host = String(e.host || '').trim();
		const wsHost = String(e.wsHost || '').trim() || host;
		return {
			host,
			port: String(e.port || '').trim() || '443',
			sni: String(e.sni || '').trim() || wsHost,
			wsHost,
			remark: String(e.remark || '').trim(),
			transports: Array.isArray(e.transports) ? e.transports.filter((t) => ['ws', 'grpc', 'h2'].includes(t)) : ['ws', 'grpc', 'h2'],
		};
	}).filter((e) => e.host);
}

/**
 * 请求级配置对象：一次请求内只读一次 D1，统一缓存
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Object} env
 * @returns {Promise<Object>} config
 */
export async function createRequestConfig(request, env, options = {}) {
	const { DB } = env;
	const settings = await cachedLoad('settings', () => loadSettings(DB));

	const wsPath = settings.ws_path || DEFAULT_WS_PATH;
	const entryTransport = settings.entry_transport || INBOUND_TRANSPORT_DEFAULT;
	const defaultOutbound = settings.default_outbound || OUTBOUND_DIRECT;
	let adminPasswordHash = settings.admin_password_hash || '';
	let adminTempPassword = null;
	// 仅后台入口生成初始密码；避免伪装页/订阅等路由提前触发生成，导致 /admin 不再展示初始密码
	if (!adminPasswordHash && options.ensureAdmin) {
		const ensured = await ensureAdminPassword(DB);
		adminPasswordHash = ensured.hash;
		adminTempPassword = ensured.tempPassword;
	}
	const proxyipRaw = settings.proxyip || '';
	// outbounds 提前加载：proxyip 出站名匹配依赖出站表
	const outbounds = await cachedLoad('outbounds', () => loadOutbounds(DB));
	// proxyip：可填 IP 或域名，支持 [host:port] 或裸 host（默认 443），也可直接填出站名（该出站代理出站），
	// 仅默认出站 direct 时生效
	let proxyipHost = '';
	let proxyipPort = 443;
	let proxyipOutbound = '';
	if (proxyipRaw) {
		// 优先匹配出站名（vless / socks5 / http 出站）：命中后 CF 目标走该出站代理
		const named = outbounds.find((o) => o.name === proxyipRaw && o.type !== OUTBOUND_DIRECT && o.type !== OUTBOUND_REJECT);
		if (named) {
			proxyipOutbound = proxyipRaw;
		} else {
			const idx = proxyipRaw.lastIndexOf(':');
			if (idx > 0 && !proxyipRaw.includes(']') && /^\d+$/.test(proxyipRaw.slice(idx + 1))) {
				proxyipHost = proxyipRaw.slice(0, idx);
				proxyipPort = Number(proxyipRaw.slice(idx + 1)) || 443;
			} else {
				proxyipHost = proxyipRaw;
			}
		}
	}
	// UDP 出站代理：出站名（仅 vless 支持 UDP）
	const udpOutbound = settings.udp_outbound || '';
	// 入口设置：多入口列表（entry_list JSON，支持多入口 + 备注 + 每入口协议），兼容旧单入口字段
	const entries = parseEntries(settings);
	const entryHost = entries.length ? entries[0].host : '';
	const entryPort = entries.length ? entries[0].port : '';
	const entrySni = entries.length ? entries[0].sni : '';
	const entryWsHost = entries.length ? entries[0].wsHost : '';

	const vlessUsers = await cachedLoad('vlessUsers', () => loadVlessUsers(DB));
	const trojanUsers = await cachedLoad('trojanUsers', () => loadTrojanUsers(DB));
	const routingRules = await cachedLoad('routingRules', () => loadRoutingRules(DB));

	// 到期流量重置（请求级幂等：traffic_reset_at 已过期才清零）
	await Promise.all([
		resetExpiredTraffic(DB, vlessUsers, 'vless_users'),
		resetExpiredTraffic(DB, trojanUsers, 'trojan_users'),
	]);

	// 入站路径映射：全局 wsPath + 各用户自定义 path（含各自 /Tun grpc 后缀）
	const inboundPathMap = buildInboundPathMap(wsPath, vlessUsers, trojanUsers);

	// uuid -> remark / password -> remark 索引（用于流量统计记录 user id）
	const vlessIndex = {};
	for (const u of vlessUsers) vlessIndex[u.uuid] = u;
	const trojanIndex = {};
	for (const u of trojanUsers) trojanIndex[u.password] = u;

	return {
		env,
		settings,
		wsPath,
		entryTransport,
		defaultOutbound,
		adminPasswordHash,
		adminTempPassword,
		proxyipHost,
		proxyipPort,
		// proxyip 出站名模式：非空时 CF 目标走该出站代理出站（替代 proxyipHost 裸连）
		proxyipOutbound,
		// proxyip 仅当默认出站为 direct（cloudflare:sockets）时生效
		proxyipDisabled: defaultOutbound !== OUTBOUND_DIRECT,
		udpOutbound,
		entryHost,
		entryPort,
		entrySni,
		entryWsHost,
		entries,
		vlessUsers,
		trojanUsers,
		outbounds,
		routingRules,
		vlessIndex,
		trojanIndex,
		// 单个 uuid 校验集合（快速查找）
		uuidSet: new Set(vlessUsers.map((u) => u.uuid.toLowerCase())),
		passwordSet: new Set(trojanUsers.map((u) => u.password)),
		// 出站按 name 索引
		outboundByName: outbounds.reduce((m, o) => { m[o.name] = o; return m; }, {}),
		// 入站路径 → 允许凭据作用域（全类型自动入站分发依据）
		inboundPathMap,
	};
}

/**
 * 生成随机 UUID (v4)
 */
export function randomUUID() {
	if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
		return globalThis.crypto.randomUUID();
	}
	// fallback
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
		const r = (Math.random() * 16) | 0;
		const v = c === 'x' ? r : (r & 0x3) | 0x8;
		return v.toString(16);
	});
}

/**
 * 将路径映射命中的 scope 列表组合为会话校验集合。
 * - 含 all（全局路径）→ 接受全部启用用户
 * - 仅用户自定义路径 → 限定该路径注册的 vless uuid / trojan password
 * @param {Array<{kind:string, credential?:string}>} scopes
 * @returns {{all:boolean, vless:Set<string>, trojan:Set<string>}}
 */
export function composeInboundScope(scopes) {
	const vless = new Set();
	const trojan = new Set();
	for (const s of scopes) {
		if (s.kind === 'all') return { all: true, vless, trojan };
		if (s.kind === 'vless' && s.credential) vless.add(s.credential);
		if (s.kind === 'trojan' && s.credential) trojan.add(s.credential);
	}
	return { all: false, vless, trojan };
}
