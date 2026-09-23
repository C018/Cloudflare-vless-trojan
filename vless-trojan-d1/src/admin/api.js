/**
 * Admin REST API handler
 */

import { hashPassword, verifyPassword, createSessionValue, verifySessionValue, parseCookies, ADMIN_COOKIE_NAME } from './auth.js';
import { clearGeoCache } from '../routing/geo.js';
import { runNetstatusTest, testProxyIp, testUdp, testOutbound } from '../netprobe.js';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function json(data, status = 200) {
	return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

async function readBody(request) {
	try {
		return await request.json();
	} catch (e) {
		return null;
	}
}

function getSecret(settings) {
	return settings.admin_cookie_secret || settings.admin_password_hash || 'vtd-insecure-secret';
}

/**
 * 后台 API 入口
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Object} config
 * @returns {Promise<Response>}
 */
export async function handleAdminApi(request, config) {
	const url = new URL(request.url);
	const path = url.pathname; // /admin/api/...
	const segments = path.split('/').filter(Boolean); // ['admin','api',...]
	const resource = segments[2] || '';
	const id = segments[3] || null;
	const method = request.method;
	const { DB, GEO_KV } = config.env;
	const settings = config.settings;
	const secret = getSecret(settings);

	// ---- 登录（免鉴权）----
	if (resource === 'login' && method === 'POST') {
		const body = await readBody(request);
		if (!body || !body.password) return json({ error: 'password required' }, 400);
		const ok = await verifyPassword(body.password, config.adminPasswordHash);
		if (!ok) return json({ error: 'invalid password' }, 401);
		const session = await createSessionValue(secret);
		return new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: {
				...JSON_HEADERS,
				'Set-Cookie': `${ADMIN_COOKIE_NAME}=${session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 86400}`
			}
		});
	}

	// ---- 其余接口需鉴权 ----
	const cookies = parseCookies(request.headers.get('Cookie'));
	const authed = await verifySessionValue(cookies[ADMIN_COOKIE_NAME], secret);
	if (!authed) return json({ error: 'unauthorized' }, 401);

	if (resource === 'logout' && method === 'POST') {
		return new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: { ...JSON_HEADERS, 'Set-Cookie': `${ADMIN_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` }
		});
	}

	// ---- settings ----
	if (resource === 'settings') {
		if (method === 'GET') {
			const { results } = await DB.prepare('SELECT key, value FROM settings').all();
			return json((results || []).reduce((m, r) => { m[r.key] = r.value; return m; }, {}));
		}
		if (method === 'PUT') {
			const body = await readBody(request);
			if (!body) return json({ error: 'bad body' }, 400);
			// 白名单：仅允许写入受支持的设置项，屏蔽已废弃的 CDN/优选 等字段
			const ALLOWED_SETTINGS = new Set([
				'ws_path', 'default_outbound', 'proxyip', 'udp_outbound',
				'disguise_title', 'disguise_subtitle',
				'entry_host', 'entry_port', 'entry_sni', 'entry_ws_host',
				'admin_password_hash', 'admin_cookie_secret',
			]);
			for (const [key, value] of Object.entries(body)) {
				if (typeof value !== 'string') continue;
				if (!ALLOWED_SETTINGS.has(key)) continue;
				await DB.prepare(
					'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
				).bind(key, value, Date.now()).run();
			}
			return json({ ok: true });
		}
		return json({ error: 'method not allowed' }, 405);
	}

	// ---- 通用 CRUD（表名映射 + 白名单校验）----
	const crudTables = {
		'vless-users': { table: 'vless_users', cols: ['uuid', 'remark', 'enable'] },
		'trojan-users': { table: 'trojan_users', cols: ['password', 'remark', 'enable'] },
		'outbounds': {
			table: 'outbounds',
			cols: ['type', 'name', 'address', 'port', 'uuid', 'path', 'tls', 'udp', 'enable', 'sort', 'username', 'password', 'sni', 'transport'],
			validate(body) {
				if (body.type !== undefined && !['socks5', 'http', 'vless'].includes(body.type)) return 'invalid outbound type';
				if (body.port !== undefined && (!Number.isInteger(Number(body.port)) || Number(body.port) <= 0 || Number(body.port) > 65535)) return 'invalid port';
				if ((body.type === 'socks5' || body.type === 'http') && !body.address) return 'address required';
				if (body.type === 'vless') {
					if (!body.uuid) return 'vless requires uuid';
					if (body.transport !== undefined && !['raw', 'ws', 'grpc', 'httpupgrade'].includes(body.transport)) return 'invalid vless transport';
				}
				if ((body.username && !body.password) || (!body.username && body.password)) return 'username and password must be set together';
				// socks5/http 不支持 UDP（仅 vless 支持），保存时强制 udp=0
				if (body.type === 'socks5' || body.type === 'http') body.udp = 0;
				// transport 仅对 vless 有意义，非 vless 一律置默认 ws
				if (body.type !== 'vless') body.transport = 'ws';
				return null;
			}
		},
		'routing-rules': { table: 'routing_rules', cols: ['rule', 'outbound', 'enable', 'sort'] },
	};
	const crud = crudTables[resource];
	if (crud) {
		return handleCrud(method, id, crud, DB, request);
	}

	// ---- stats ----
	if (resource === 'stats' && method === 'GET') {
		const [vless, trojan] = await Promise.all([
			DB.prepare('SELECT remark, uuid, up, down FROM vless_users ORDER BY (up + down) DESC').all(),
			DB.prepare('SELECT remark, password, up, down FROM trojan_users ORDER BY (up + down) DESC').all(),
		]);
		return json({ vless: vless.results || [], trojan: trojan.results || [] });
	}

	// ---- geo update ----
	if (resource === 'geo' && segments[3] === 'update' && method === 'POST') {
		try {
			const count = await updateGeo(DB, GEO_KV);
			return json({ ok: true, updated: count });
		} catch (e) {
			return json({ error: e.message }, 500);
		}
	}

	// ---- netstatus：网络状态检测（多目标并行采样，约 10-15 秒）----
	if (resource === 'netstatus' && segments[3] === 'test' && method === 'POST') {
		try {
			return json(await runNetstatusTest(config, (m) => console.log(m)));
		} catch (e) {
			return json({ ok: false, error: e.message }, 500);
		}
	}

	// ---- 测试：proxyip / udp / outbound ----
	if (resource === 'test') {
		if (segments[3] === 'proxyip' && method === 'POST') {
			try {
				return json(await testProxyIp(config, (m) => console.log(m)));
			} catch (e) {
				return json({ ok: false, error: e.message }, 500);
			}
		}
		if (segments[3] === 'udp' && method === 'POST') {
			try {
				return json(await testUdp(config, (m) => console.log(m)));
			} catch (e) {
				return json({ ok: false, error: e.message }, 500);
			}
		}
		if (segments[3] === 'outbound' && segments[4] && method === 'POST') {
			const row = await DB.prepare('SELECT * FROM outbounds WHERE id = ?').bind(Number(segments[4])).first();
			if (!row) return json({ ok: false, error: 'outbound not found' }, 404);
			try {
				return json(await testOutbound(config, row, (m) => console.log(m)));
			} catch (e) {
				return json({ ok: false, error: e.message }, 500);
			}
		}
	}

	return json({ error: 'not found' }, 404);
}

async function handleCrud(method, id, crud, DB, request) {
	const { table, cols } = crud;
	const idCol = table === 'vless_users' || table === 'trojan_users' ? 'id' : 'id';

	if (method === 'GET') {
		const { results } = await DB.prepare(`SELECT * FROM ${table} ORDER BY id`).all();
		return json(results || []);
	}
	if (method === 'POST') {
		const body = await readBody(request);
		if (!body) return json({ error: 'bad body' }, 400);
		if (crud.validate) { const err = crud.validate(body); if (err) return json({ error: err }, 400); }
		const keys = cols.filter((c) => body[c] !== undefined);
		if (keys.length === 0) return json({ error: 'no fields' }, 400);
		const placeholders = keys.map(() => '?').join(',');
		const values = keys.map((c) => body[c]);
		const { meta } = await DB.prepare(
			`INSERT INTO ${table} (${keys.join(',')}) VALUES (${placeholders})`
		).bind(...values).run();
		return json({ ok: true, id: meta.last_row_id });
	}
	if (method === 'PUT' && id) {
		const body = await readBody(request);
		if (!body) return json({ error: 'bad body' }, 400);
		if (crud.validate) { const err = crud.validate(body); if (err) return json({ error: err }, 400); }
		const keys = cols.filter((c) => body[c] !== undefined);
		if (keys.length === 0) return json({ error: 'no fields' }, 400);
		const sets = keys.map((c) => `${c} = ?`).join(',');
		const values = keys.map((c) => body[c]);
		await DB.prepare(`UPDATE ${table} SET ${sets} WHERE ${idCol} = ?`).bind(...values, Number(id)).run();
		return json({ ok: true });
	}
	if (method === 'DELETE' && id) {
		await DB.prepare(`DELETE FROM ${table} WHERE ${idCol} = ?`).bind(Number(id)).run();
		return json({ ok: true });
	}
	return json({ error: 'method not allowed' }, 405);
}

/**
 * 手动触发 geo 库更新：读取所有规则引用的分类，写 KV
 */
export async function updateGeo(DB, GEO_KV) {
	const { results } = await DB.prepare('SELECT rule FROM routing_rules').all();
	const categories = { geosite: new Set(), geoip: new Set() };
	for (const row of results || []) {
		const s = String(row.rule || '').trim();
		let m = s.match(/^geosite:(.+)$/i);
		if (m) m[1].split(',').forEach((x) => categories.geosite.add(x.trim()));
		m = s.match(/^geoip:(.+)$/i);
		if (m) m[1].split(',').forEach((x) => categories.geoip.add(x.trim()));
	}

	let updated = 0;
	for (const type of ['geosite', 'geoip']) {
		for (const category of categories[type]) {
			try {
				const data = await fetchCategory(type, category);
				if (data && data.length > 0) {
					await GEO_KV.put(`${type}:${category}`, JSON.stringify(data));
					updated++;
				}
			} catch (e) { /* skip category */ }
		}
	}
	await GEO_KV.put('geo:version', new Date().toISOString());
	clearGeoCache();
	return updated;
}

/**
 * 从 MetaCubeX sing-geosite / sing-geoip 仓库拉取分类 JSON
 */
async function fetchCategory(type, category) {
	const repo = type === 'geosite' ? 'MetaCubeX/sing-geosite' : 'MetaCubeX/sing-geoip';
	const url = `https://raw.githubusercontent.com/${repo}/rule-set/${category}.json`;
	const res = await fetch(url, { cf: { cacheTtl: 86400 } });
	if (!res.ok) {
		// 兜底：geosite 的 category 也可能不带 -geosite 后缀（sing-geosite 已按裸名）
		return null;
	}
	const text = await res.text();
	// sing-geosite / sing-geoip rule-set 为 JSON：geosite 收集 rules[].domain 与 rules[].domain_suffix（去前导点）；geoip 收集 rules[].ip_cidr
	let data;
	try {
		data = JSON.parse(text);
	} catch (e) {
		return null;
	}
	const rules = [];
	const push = (v) => { if (typeof v === 'string' && v && rules.length < 20000) rules.push(v); };
	for (const rule of data.rules || []) {
		if (type === 'geosite') {
			for (const d of rule.domain || []) push(d);
			for (const d of rule.domain_suffix || []) push(String(d).replace(/^\.+/, ''));
		} else {
			for (const c of rule.ip_cidr || []) push(c);
		}
	}
	return rules;
}
