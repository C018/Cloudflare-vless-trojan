/**
 * Defaults + request-scoped config loader (D1 backed)
 */

import { DEFAULT_WS_PATH, OUTBOUND_DIRECT } from './constants.js';
import { hashPassword } from '../admin/auth.js';

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
 * @returns {Promise<Array<{id:number,uuid:string,remark:string,up:number,down:number}>>}
 */
export async function loadVlessUsers(db) {
	try {
		const { results } = await db.prepare(
			'SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id'
		).all();
		return results || [];
	} catch (e) {
		return [];
	}
}

/**
 * 读取启用的 trojan 用户
 */
export async function loadTrojanUsers(db) {
	try {
		const { results } = await db.prepare(
			'SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id'
		).all();
		return results || [];
	} catch (e) {
		return [];
	}
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
	} catch (e) { /* ignore */ }
	return { hash, tempPassword };
}

/**
 * 请求级配置对象：一次请求内只读一次 D1，统一缓存
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Object} env
 * @returns {Promise<Object>} config
 */
export async function createRequestConfig(request, env, options = {}) {
	const { DB } = env;
	const settings = await loadSettings(DB);

	const wsPath = settings.ws_path || DEFAULT_WS_PATH;
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
	// proxyip：可填 IP 或域名，支持 [host:port] 或裸 host（默认 443），仅默认出站 direct 时生效
	let proxyipHost = '';
	let proxyipPort = 443;
	if (proxyipRaw) {
		const idx = proxyipRaw.lastIndexOf(':');
		if (idx > 0 && !proxyipRaw.includes(']') && /^\d+$/.test(proxyipRaw.slice(idx + 1))) {
			proxyipHost = proxyipRaw.slice(0, idx);
			proxyipPort = Number(proxyipRaw.slice(idx + 1)) || 443;
		} else {
			proxyipHost = proxyipRaw;
		}
	}
	// UDP 出站代理：出站名（仅 vless 支持 UDP）
	const udpOutbound = settings.udp_outbound || '';
	// 入口设置：设置后节点/订阅生成使用入口配置，未设置则使用当前域名
	const entryHost = settings.entry_host || '';
	const entryPort = settings.entry_port || '';
	const entrySni = settings.entry_sni || '';
	const entryWsHost = settings.entry_ws_host || '';

	const vlessUsers = await loadVlessUsers(DB);
	const trojanUsers = await loadTrojanUsers(DB);
	const outbounds = await loadOutbounds(DB);
	const routingRules = await loadRoutingRules(DB);

	// uuid -> remark / password -> remark 索引（用于流量统计记录 user id）
	const vlessIndex = {};
	for (const u of vlessUsers) vlessIndex[u.uuid] = u;
	const trojanIndex = {};
	for (const u of trojanUsers) trojanIndex[u.password] = u;

	return {
		env,
		settings,
		wsPath,
		defaultOutbound,
		adminPasswordHash,
		adminTempPassword,
		proxyipHost,
		proxyipPort,
		// proxyip 仅当默认出站为 direct（cloudflare:sockets）时生效
		proxyipDisabled: defaultOutbound !== OUTBOUND_DIRECT,
		udpOutbound,
		entryHost,
		entryPort,
		entrySni,
		entryWsHost,
		vlessUsers,
		trojanUsers,
		outbounds,
		routingRules,
		vlessIndex,
		trojanIndex,
		// 单个 uuid 校验集合（快速查找）
		uuidSet: new Set(vlessUsers.map((u) => u.uuid)),
		passwordSet: new Set(trojanUsers.map((u) => u.password)),
		// 出站按 name 索引
		outboundByName: outbounds.reduce((m, o) => { m[o.name] = o; return m; }, {}),
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
