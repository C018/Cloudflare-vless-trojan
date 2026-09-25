/**
 * Admin REST API handler
 */

import { hashPassword, verifyPassword, createSessionValue, verifySessionValue, parseCookies, ADMIN_COOKIE_NAME } from './auth.js';
import { VERSION } from '../version.js';
import { clearGeoCache } from '../routing/geo.js';
import { GEO_KV_VERSION } from '../config/constants.js';
import { runNetstatusTest, testProxyIp, testUdp, testOutbound, testRoute } from '../netprobe.js';
import { unzlibSync } from 'fflate';
import { invalidateConfigCache } from '../config/defaults.js';

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
export async function handleAdminApi(request, config, ctx) {
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

	// ---- 系统版本 ----
	if (resource === 'version' && method === 'GET') {
		return json({ ok: true, version: VERSION });
	}

	// 旧库自动迁移：vless_users / trojan_users 补充入站路径、到期、流量限制等列（幂等）
	await ensureUserColumns(DB);

	// ---- settings ----
	if (resource === 'settings') {
		if (method === 'GET') {
			const { results } = await DB.prepare('SELECT key, value FROM settings').all();
			return json((results || []).reduce((m, r) => { m[r.key] = r.value; return m; }, {}));
		}
		if (method === 'PUT') {
			const body = await readBody(request);
			if (!body) return json({ error: 'bad body' }, 400);
			// 白名单：仅允许写入受支持的设置项，屏蔽已废弃的 CDN/优选/entry_transport 等字段。
			// 入站已改为全类型自动（ws/grpc/h2），entry_transport 不再参与入站分发，禁止再写入。
			const ALLOWED_SETTINGS = new Set([
				'ws_path', 'default_outbound', 'proxyip', 'udp_outbound',
				'disguise_title', 'disguise_subtitle',
				'entry_host', 'entry_port', 'entry_sni', 'entry_ws_host', 'entry_list',
				'admin_password_hash', 'admin_cookie_secret',
			]);
			// 多入口列表结构校验：必须为 JSON 数组，每项含 host 且 transports 仅允许 ws/grpc/h2
			if (body.entry_list !== undefined) {
				try {
					const arr = JSON.parse(body.entry_list);
					if (!Array.isArray(arr) || arr.some((e) => !e || !String(e.host || '').trim())) {
						return json({ error: 'entry_list 必须为入口数组（每项需包含 host）' }, 400);
					}
					if (arr.some((e) => Array.isArray(e.transports) && e.transports.some((t) => !['ws', 'grpc', 'h2'].includes(t)))) {
						return json({ error: 'entry_list transports 仅允许 ws / grpc / h2' }, 400);
					}
				} catch (e) {
					return json({ error: 'entry_list 不是合法 JSON 数组' }, 400);
				}
			}
			for (const [key, value] of Object.entries(body)) {
				if (typeof value !== 'string') continue;
				if (!ALLOWED_SETTINGS.has(key)) continue;
				await DB.prepare(
					'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
				).bind(key, value, Date.now()).run();
			}
			// 后台修改设置成功后主动失效进程级缓存，避免改动 30s 内不生效
			invalidateConfigCache('settings');
			return json({ ok: true });
		}
		return json({ error: 'method not allowed' }, 405);
	}

	// ---- 通用 CRUD（表名映射 + 白名单校验）----
	const crudTables = {
		'vless-users': { table: 'vless_users', cacheKey: 'vlessUsers', cols: ['uuid', 'remark', 'enable', 'path', 'expire_at', 'traffic_limit', 'traffic_reset_at'] },
		'trojan-users': { table: 'trojan_users', cacheKey: 'trojanUsers', cols: ['password', 'remark', 'enable', 'path', 'expire_at', 'traffic_limit', 'traffic_reset_at'] },
		'outbounds': {
			table: 'outbounds',
			cacheKey: 'outbounds',
			cols: ['type', 'name', 'address', 'port', 'uuid', 'path', 'tls', 'udp', 'enable', 'sort', 'username', 'password', 'sni', 'transport'],
			validate(body) {
				if (body.type !== undefined && !['socks5', 'http', 'vless'].includes(body.type)) return 'invalid outbound type';
				if (body.port !== undefined && (!Number.isInteger(Number(body.port)) || Number(body.port) <= 0 || Number(body.port) > 65535)) return 'invalid port';
				if ((body.type === 'socks5' || body.type === 'http') && !body.address) return 'address required';
				if (body.type === 'vless') {
					if (!body.uuid) return 'vless requires uuid';
					if (body.transport !== undefined && !['raw', 'ws', 'grpc', 'httpupgrade', 'h2'].includes(body.transport)) return 'invalid vless transport';
				}
				if ((body.username && !body.password) || (!body.username && body.password)) return 'username and password must be set together';
				// socks5/http 不支持 UDP（仅 vless 支持），保存时强制 udp=0
				if (body.type === 'socks5' || body.type === 'http') body.udp = 0;
				// transport 仅对 vless 有意义，非 vless 一律置默认 ws
				if (body.type !== 'vless') body.transport = 'ws';
				return null;
			}
		},
		'routing-rules': { table: 'routing_rules', cacheKey: 'routingRules', cols: ['rule', 'outbound', 'enable', 'sort'] },
	};
	const crud = crudTables[resource];
	if (crud) {
		return handleCrud(method, id, crud, DB, request);
	}

	// ---- stats ----
	if (resource === 'stats' && method === 'GET') {
		const [vless, trojan] = await Promise.all([
			DB.prepare('SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC').all(),
			DB.prepare('SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC').all(),
		]);
		const now = Math.floor(Date.now() / 1000);
		const decorate = (rows) => (rows || []).map((r) => {
			const up = Number(r.up || 0);
			const down = Number(r.down || 0);
			const limit = Number(r.traffic_limit || 0);
			const used = up + down;
			return {
				...r,
				used,
				remaining: limit > 0 ? Math.max(0, limit - used) : null,
				expired: r.expire_at > 0 && r.expire_at < now,
				limitReached: limit > 0 && used >= limit,
			};
		});
		return json({ vless: decorate(vless.results), trojan: decorate(trojan.results) });
	}

	// ---- geo update / status ----
	if (resource === 'geo' && segments[3] === 'update' && method === 'POST') {
		try {
			// 互斥锁：同一时间仅允许一个更新任务（带 10 分钟 TTL，防止队列重试耗尽/异常退出后锁卡死）
			const updating = await GEO_KV.get('geo:updating');
			if (updating === '1') {
				return json({ ok: true, started: false, updating: true });
			}
			await GEO_KV.put('geo:updating', '1', { expirationTtl: 600 });
			// 优先走 Workers Queues：consumer 独立执行（不受请求 30s 限制，失败自动重试）
			if (config.env && config.env.GEO_QUEUE && typeof config.env.GEO_QUEUE.send === 'function') {
				await config.env.GEO_QUEUE.send({ kind: 'geo-update' });
				// 入队成功后立即写初始进度状态，避免消费者尚未消费时前端读到空状态而显示 0/0
				await GEO_KV.put('geo:update_status', JSON.stringify({
					startedAt: Date.now(),
					state: 'updating', step: 0, total: 0, updated: 0, failed: [],
					current: '', message: '已入队，等待消费者执行…'
				})).catch(() => {});
				return json({ ok: true, started: true, queued: true, updating: true });
			}
			if (ctx && typeof ctx.waitUntil === 'function') {
				// 无队列兜底：后台异步更新 + 分阶段进度写 KV（geo:update_status），前端轮询 geo/status 展示
				ctx.waitUntil(runGeoUpdateTask(DB, GEO_KV));
				return json({ ok: true, started: true, updating: true });
			}
			// 无 ctx 兜底：同步执行（兼容旧调用方）
			const detail = await runGeoUpdateTask(DB, GEO_KV);
			return json({ ok: true, started: false, updated: detail.updated, total: detail.total, failed: detail.failed });
		} catch (e) {
			await GEO_KV.put('geo:updating', '0').catch(() => {});
			return json({ error: e.message }, 500);
		}
	}
	if (resource === 'geo' && segments[3] === 'status' && method === 'GET') {
		const [updating, statusRaw, version] = await Promise.all([
			GEO_KV.get('geo:updating'),
			GEO_KV.get('geo:update_status'),
			GEO_KV.get(GEO_KV_VERSION),
		]);
		let status = null;
		if (statusRaw) { try { status = JSON.parse(statusRaw); } catch (e) { /* ignore */ } }
		return json({ ok: true, updating: updating === '1', version: version || null, status });
	}

	// ---- netstatus：网络状态检测（多目标并行采样，约 10-15 秒）----
	if (resource === 'netstatus' && segments[3] === 'test' && method === 'POST') {
		try {
			return json(await runNetstatusTest(config, (m) => console.log(m)));
		} catch (e) {
			return json({ ok: false, error: e.message }, 500);
		}
	}

	// ---- 路由测试：按真实分流判定返回域名路由走向（direct / proxyip / outbound）----
	if (resource === 'route-test' && method === 'POST') {
		try {
			const body = await readBody(request);
			const domain = body && body.domain ? String(body.domain).trim() : '';
			if (!domain) return json({ ok: false, error: '请填写要测试的域名或 IP' }, 400);
			return json(await testRoute(config, domain, (m) => console.log(m)));
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

async function ensureOutboundTransportColumn(DB) {
	// 老库缺少 transport 列时自动 ALTER，避免保存出站代理报 no such column（幂等，重复执行忽略）
	try {
		const { results } = await DB.prepare("SELECT name FROM pragma_table_info('outbounds')").all();
		if ((results || []).some((r) => r.name === 'transport')) return;
		await DB.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run();
		console.log('[admin] outbounds.transport column added (migration)');
	} catch (e) {
		console.log('[admin] outbounds transport migration skipped: ' + e.message);
	}
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
		if (table === 'outbounds') await ensureOutboundTransportColumn(DB);
		const keys = cols.filter((c) => body[c] !== undefined);
		if (keys.length === 0) return json({ error: 'no fields' }, 400);
		const placeholders = keys.map(() => '?').join(',');
		const values = keys.map((c) => body[c]);
		const { meta } = await DB.prepare(
			`INSERT INTO ${table} (${keys.join(',')}) VALUES (${placeholders})`
		).bind(...values).run();
		if (crud.cacheKey) invalidateConfigCache(crud.cacheKey);
		return json({ ok: true, id: meta.last_row_id });
	}
	if (method === 'PUT' && id) {
		const body = await readBody(request);
		if (!body) return json({ error: 'bad body' }, 400);
		if (crud.validate) { const err = crud.validate(body); if (err) return json({ error: err }, 400); }
		if (table === 'outbounds') await ensureOutboundTransportColumn(DB);
		const keys = cols.filter((c) => body[c] !== undefined);
		if (keys.length === 0) return json({ error: 'no fields' }, 400);
		const sets = keys.map((c) => `${c} = ?`).join(',');
		const values = keys.map((c) => body[c]);
		await DB.prepare(`UPDATE ${table} SET ${sets} WHERE ${idCol} = ?`).bind(...values, Number(id)).run();
		if (crud.cacheKey) invalidateConfigCache(crud.cacheKey);
		return json({ ok: true });
	}
	if (method === 'DELETE' && id) {
		await DB.prepare(`DELETE FROM ${table} WHERE ${idCol} = ?`).bind(Number(id)).run();
		if (crud.cacheKey) invalidateConfigCache(crud.cacheKey);
		return json({ ok: true });
	}
	return json({ error: 'method not allowed' }, 405);
}

// 内置默认 geo 分类清单（修复2：不再依赖 routing_rules 表）
// geosite: v2fly/domain-list-community data/ 下常用分类（已剔除源站不存在的分类）
// geoip:   SagerNet/sing-geoip rule-set 下 geoip-{category}.srs（该分支仅含国家/地区代码，
//          此处取常用国家/地区；全部经源站验证存在）
const DEFAULT_GEO_CATEGORIES = {
	geosite: [
		'cn', 'apple', 'google', 'microsoft', 'facebook', 'twitter', 'telegram',
		'github', 'netflix', 'youtube', 'spotify', 'discord', 'tiktok', 'paypal',
		'steam', 'cloudflare', 'openai', 'amazon', 'whatsapp', 'instagram',
		'linkedin', 'mozilla', 'adobe', 'speedtest', 'oracle', 'digitalocean',
		'vultr', 'jetbrains', 'gitee', 'baidu', 'aliyun', 'tencent',
		'jd', 'bilibili', 'douyin', 'zhihu', 'iqiyi', 'youku', 'xiaomi', 'huawei'
	],
	geoip: [
		'cn', 'hk', 'mo', 'tw', 'jp', 'kr', 'sg', 'my', 'th', 'vn',
		'id', 'ph', 'us', 'ca', 'gb', 'de', 'fr', 'nl', 'se', 'au',
		'nz', 'ru', 'in', 'br', 'ar', 'mx', 'za', 'tr', 'ae', 'sa',
		'il', 'es', 'it', 'ch', 'at', 'be', 'dk', 'fi', 'no', 'pl',
		'pt', 'ie', 'cz', 'hu', 'ro', 'ua', 'kz'
	]
};

/**
 * 手动触发 geo 库更新：按内置默认分类清单全量更新并写 KV，返回真实计数。
 * 修复2：原实现从 routing_rules 表解析 geosite:/geoip: 分类，线上无此类规则时
 * total=0/updated=0；现改为不依赖现有规则，直接按 DEFAULT_GEO_CATEGORIES 全量更新。
 * DB 参数保留仅为兼容现有调用方签名（cron.js / api.js 均传 DB, GEO_KV）。
 * @returns {Promise<{updated:number, total:number, failed:string[]}>}
 */
export async function updateGeo(DB, GEO_KV, onProgress) {
	const categories = {
		geosite: new Set(DEFAULT_GEO_CATEGORIES.geosite),
		geoip: new Set(DEFAULT_GEO_CATEGORIES.geoip)
	};
	const totalCategories = DEFAULT_GEO_CATEGORIES.geosite.length + DEFAULT_GEO_CATEGORIES.geoip.length;
	const notify = (patch) => {
		if (typeof onProgress === 'function') {
			try { onProgress(patch); } catch (e) { /* ignore */ }
		}
	};

	const detail = { updated: 0, total: 0, failed: [] };
	let step = 0;
	for (const type of ['geosite', 'geoip']) {
		for (const category of categories[type]) {
			detail.total++;
			step++;
			notify({ state: 'updating', step, total: totalCategories, current: `${type}:${category}`, updated: detail.updated, failed: detail.failed, message: `拉取 ${type}:${category}` });
			try {
				const data = await fetchCategory(type, category);
				if (data && data.length > 0) {
					await GEO_KV.put(`${type}:${category}`, JSON.stringify(data));
					detail.updated++;
				} else {
					detail.failed.push(`${type}:${category} (empty rules)`);
				}
			} catch (e) {
				detail.failed.push(`${type}:${category} (${e.message || e})`);
			}
		}
	}
	await GEO_KV.put(GEO_KV_VERSION, new Date().toISOString());
	clearGeoCache();
	return detail;
}

/**
 * 后台异步执行 geo 更新并分阶段写进度到 KV（geo:update_status）。
 * 供手动更新按钮使用，配合 ctx.waitUntil 保活；cron 仍直接调用 updateGeo（无进度副作用）。
 */
export async function runGeoUpdateTask(DB, GEO_KV) {
	const startedAt = Date.now();
	const save = (patch) => GEO_KV.put('geo:update_status', JSON.stringify({ startedAt, ...patch })).catch(() => {});
	try {
		await save({ state: 'updating', step: 0, total: 0, updated: 0, failed: [], current: '', message: '开始更新' });
		const detail = await updateGeo(DB, GEO_KV, (p) => save({ ...p }));
		await save({ state: 'done', step: detail.total, total: detail.total, updated: detail.updated, failed: detail.failed, current: '', message: '更新完成' });
		await GEO_KV.put('geo:updating', '0').catch(() => {});
		return detail;
	} catch (e) {
		await save({ state: 'error', message: e.message || String(e), failed: [] }).catch(() => {});
		// 失败时不清 geo:updating 锁：queue 路径由队列重试直至成功或 TTL(600s) 自动解锁；waitUntil/同步路径同理依赖 TTL 兜底
		throw e;
	}
}

/**
 * 拉取分类规则，返回 string[]：
 * - geosite：v2fly/domain-list-community 纯文本源（每行一个域名，支持 include 递归 / 注释 /
 *   full:/domain:/keyword:/regexp: 前缀）。sing-geosite 官方仓库已无 JSON（仅 .srs 二进制），
 *   其数据源即 v2fly/domain-list-community，故直接改用该源。
 * - geoip：解析 SagerNet/sing-geoip 官方 rule-set 分支 .srs 二进制（SRS v1：magic + zlib +
 *   rules；规则项 IPCIDR 为 ipset 区间编码），区间转 CIDR 列表。
 * 两个源均提供 raw.githubusercontent 主源 + jsDelivr CDN 兜底。
 */
async function fetchCategory(type, category) {
	if (type === 'geosite') {
		const domains = await fetchV2flyGeosite(category, new Set());
		if (domains.length === 0) throw new Error('empty geosite rules');
		return domains;
	}
	const ranges = await fetchSingGeoipSrs(category);
	const cidrs = [];
	for (const [from, to] of ranges) {
		if (from.length === 4) {
			cidrs.push(...rangeToCidrsV4(from, to));
		} else {
			cidrs.push(...rangeToCidrsV6(from, to));
		}
		if (cidrs.length >= 30000) break;
	}
	if (cidrs.length === 0) throw new Error('empty geoip cidrs');
	return cidrs;
}

/* ---------- geosite: v2fly/domain-list-community ---------- */

const V2FLY_GEO_BASE = 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/';
const V2FLY_GEO_CDN = 'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/';
const GEO_MAX_ITEMS = 20000;

async function fetchV2flyGeosite(category, visited) {
	if (visited.has(category)) return [];
	visited.add(category);
	const encoded = encodeURIComponent(category);
	const urls = [V2FLY_GEO_BASE + encoded, V2FLY_GEO_CDN + encoded];
	let lastErr = null;
	for (const url of urls) {
		try {
			const res = await fetch(url, { cf: { cacheTtl: 86400 } });
			if (!res.ok) { lastErr = new Error(`HTTP ${res.status}`); continue; }
			const text = await res.text();
			const out = [];
			for (let line of text.split('\n')) {
				line = line.trim();
				if (!line || line.startsWith('#')) continue;
				if (line.startsWith('include:')) {
					// v2fly include 可带属性过滤（如 "include:deepin @-!cn"），此处取分类名（@ 前 token），属性过滤从简
					const sub = line.slice(8).trim().split(/\s+/)[0];
					if (sub) out.push(...(await fetchV2flyGeosite(sub, visited)));
					continue;
				}
				let v = line;
				if (v.startsWith('full:')) v = v.slice(5);
				else if (v.startsWith('domain:')) v = v.slice(7);
				else if (v.startsWith('keyword:') || v.startsWith('regexp:')) continue; // 消费端仅后缀匹配
				v = v.replace(/\s+@[^\s#]+/g, ''); // 剥离行尾 @属性 标记（如 "example.com @cn"），不做属性筛选
				const hash = v.indexOf('#');
				if (hash >= 0) v = v.slice(0, hash);
				v = v.trim().toLowerCase().replace(/^\.+/, '');
				if (v && out.length < GEO_MAX_ITEMS) out.push(v);
			}
			return out;
		} catch (e) {
			lastErr = e;
		}
	}
	throw lastErr || new Error('v2fly geosite fetch failed');
}

/* ---------- geoip: sing-geoip SRS 解析 ---------- */

const SING_GEOIP_BASE = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/';
const SING_GEOIP_CDN = 'https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/';
const GEOIP_MAX_CIDRS = 30000;

async function fetchSingGeoipSrs(category) {
	const encoded = encodeURIComponent(category);
	// sing-geoip rule-set 分支文件名为 geoip-{category}.srs（与 sing-geosite 的 geosite-{category}.srs 同规则）
	const urls = [SING_GEOIP_BASE + 'geoip-' + encoded + '.srs', SING_GEOIP_CDN + 'geoip-' + encoded + '.srs'];
	let lastErr = null;
	for (const url of urls) {
		try {
			const res = await fetch(url, { cf: { cacheTtl: 86400 } });
			if (!res.ok) { lastErr = new Error(`HTTP ${res.status}`); continue; }
			const buf = new Uint8Array(await res.arrayBuffer());
			if (buf.length < 5 || buf[0] !== 0x53 || buf[1] !== 0x52 || buf[2] !== 0x53) {
				lastErr = new Error('bad srs magic');
				continue;
			}
			if (buf[3] > 1) { lastErr = new Error(`unsupported srs version ${buf[3]}`); continue; }
			let payload;
			try {
				payload = unzlibSync(buf.subarray(4));
			} catch (e) {
				lastErr = new Error('zlib inflate failed');
				continue;
			}
			return parseSrsGeoip(payload);
		} catch (e) {
			lastErr = e;
		}
	}
	throw lastErr || new Error('sing-geoip srs fetch failed');
}

/** 解析 SRS v1：uvarint rule_count + rules。每个 rule：type(1B)，0=default。 */
function parseSrsGeoip(payload) {
	let pos = 0;
	const count = readUvarint(payload, pos); pos = count.p;
	const ranges = [];
	for (let ri = 0; ri < count.v; ri++) {
		const ruleType = payload[pos++];
		if (ruleType !== 0) throw new Error(`geoip logical rule unsupported (type ${ruleType})`);
		for (;;) {
			const itemType = payload[pos++];
			if (itemType === 0xff) break;
			if (itemType === 5 || itemType === 6) { // SourceIPCIDR / IPCIDR
				if (payload[pos++] !== 1) throw new Error('bad ipset version');
				const len = readUint64BE(payload, pos); pos += 8;
				for (let j = 0; j < len && ranges.length < GEOIP_MAX_CIDRS * 2; j++) {
					let alen = readUvarint(payload, pos); pos = alen.p;
					const from = payload.subarray(pos, pos + alen.v); pos += alen.v;
					alen = readUvarint(payload, pos); pos = alen.p;
					const to = payload.subarray(pos, pos + alen.v); pos += alen.v;
					if (from.length !== to.length || (from.length !== 4 && from.length !== 16)) {
						throw new Error('bad ipset addr');
					}
					ranges.push([from, to]);
				}
			} else if (itemType === 0 || itemType === 7 || itemType === 9) { // QueryType / SourcePort / Port: uint16 slice
				const n = readUvarint(payload, pos); pos = n.p;
				pos += n.v * 2;
			} else if (itemType === 1 || itemType === 3 || itemType === 4 || itemType === 8 ||
				itemType === 10 || itemType === 11 || itemType === 12 || itemType === 13 ||
				itemType === 14 || itemType === 15 || itemType === 17 || itemType === 18 ||
				itemType === 19 || itemType === 20 || itemType === 21 || itemType === 22 || itemType === 23) { // string list
				const n = readUvarint(payload, pos); pos = n.p;
				for (let j = 0; j < n.v; j++) { const l = readUvarint(payload, pos); pos = l.p; pos += l.v; }
			} else {
				throw new Error(`geoip unsupported item type ${itemType}`);
			}
		}
	}
	return ranges;
}

function readUvarint(buf, pos) {
	let r = 0, s = 0;
	for (;;) {
		const x = buf[pos++];
		r |= (x & 0x7f) << s;
		if (!(x & 0x80)) break;
		s += 7;
		if (s > 63) throw new Error('uvarint overflow');
	}
	return { v: r, p: pos };
}

/** uint64 BigEndian → Number（rule/range 数量级远小于 2^53，安全） */
function readUint64BE(buf, pos) {
	let r = 0;
	for (let i = 0; i < 8; i++) r = r * 256 + buf[pos + i];
	return r;
}

/** IPv4 区间 [from,to]（4 字节 Uint8Array）→ CIDR 列表（number 运算，<2^32 安全） */
function rangeToCidrsV4(from, to) {
	let s = ((from[0] << 24) >>> 0) + (from[1] << 16) + (from[2] << 8) + from[3];
	const e = ((to[0] << 24) >>> 0) + (to[1] << 16) + (to[2] << 8) + to[3];
	const out = [];
	while (s <= e) {
		let shift = 0;
		for (;;) {
			const block = 1 << (shift + 1);
			if ((s & (block - 1)) !== 0) break;
			if (s + block - 1 > e) break;
			shift++;
		}
		out.push(`${(s >>> 24)}.${(s >>> 16) & 0xff}.${(s >>> 8) & 0xff}.${s & 0xff}/${32 - shift}`);
		s += 1 << shift;
	}
	return out;
}

/** IPv6 区间 → CIDR 列表（BigInt 运算） */
function rangeToCidrsV6(from, to) {
	let s = 0n, e = 0n;
	for (const b of from) s = (s << 8n) | BigInt(b);
	for (const b of to) e = (e << 8n) | BigInt(b);
	const out = [];
	while (s <= e) {
		let shift = 0n;
		for (;;) {
			const block = 1n << (shift + 1n);
			if ((s & (block - 1n)) !== 0n) break;
			if (s + block - 1n > e) break;
			shift++;
		}
		out.push(`${intToIpv6(s)}/${128 - Number(shift)}`);
		s += 1n << shift;
	}
	return out;
}

/** BigInt → IPv6 字符串（最长连续 0 段压缩为 ::） */
function intToIpv6(n) {
	const hextets = [];
	for (let i = 7; i >= 0; i--) hextets.push(Number((n >> BigInt(i * 16)) & 0xffffn));
	let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
	for (let i = 0; i < 8; i++) {
		if (hextets[i] === 0) {
			if (curStart < 0) curStart = i;
			curLen++;
			if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
		} else {
			curStart = -1; curLen = 0;
		}
	}
	let s = '';
	for (let i = 0; i < 8; i++) {
		if (i === bestStart && bestLen >= 2) {
			s += (s.length > 0 && !s.endsWith(':')) ? '::' : '::';
			i += bestLen - 1;
		} else {
			if (s.length > 0 && !s.endsWith(':')) s += ':';
			s += hextets[i].toString(16);
		}
	}
	return s;
}

/**
 * 旧库自动迁移：vless_users / trojan_users 补充入站路径、到期时间、流量限制、流量重置列（幂等）
 */
async function ensureUserColumns(DB) {
	const ADD_COLUMNS = [
		['path', "TEXT DEFAULT ''"],
		['expire_at', 'INTEGER DEFAULT 0'],
		['traffic_limit', 'INTEGER DEFAULT 0'],
		['traffic_reset_at', 'INTEGER DEFAULT 0'],
	];
	for (const table of ['vless_users', 'trojan_users']) {
		try {
			const { results } = await DB.prepare(`SELECT name FROM pragma_table_info('${table}')`).all();
			const names = new Set((results || []).map((r) => r.name));
			for (const [col, def] of ADD_COLUMNS) {
				if (names.has(col)) continue;
				await DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`).run();
				console.log(`[admin] ${table}.${col} column added (migration)`);
			}
		} catch (e) {
			console.log(`[admin] ${table} migration skipped: ${e.message}`);
		}
	}
}
