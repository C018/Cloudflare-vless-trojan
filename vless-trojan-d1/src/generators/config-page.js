/**
 * Single-node config page generator
 * 入站支持 ws / grpc / h2 / xhttp 共享同一入站路径，页面按入口场景展示节点链接：
 *  - 无入口：当前请求域名 + 全协议
 *  - 单入口：该入口域名 + 入口勾选协议 + 入口备注
 *  - 多入口：顶部显示"多入口"，逐入口展示备注与勾选协议（不暴露具体域名）
 */

import { buildVlessLink, buildTrojanLink, nodeName, INBOUND_TRANSPORTS } from './subscription.js';

/** 传输类型展示名 */
const TRANSPORT_NAMES = {
	ws: 'WebSocket (ws)',
	grpc: 'gRPC',
	h2: 'HTTP/2 (h2)',
	xhttp: 'XHTTP (stream-one)',
};

/** HTML 转义：入口备注为用户输入，防止注入破坏页面结构 */
function esc(s) {
	return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/**
 * /{uuid|password} 页面：展示该凭据对应的节点链接
 * @param {Object} config
 * @param {Object} p {host, port, tls, wsHost, sni, credential, kind, path, transports, entries}
 *   entries: 已解析入口数组（config.entries）。为空/未传 -> 当前域名+全协议；
 *            长度 1 -> 单入口视图；长度 >1 -> 多入口视图（顶部"多入口"，逐入口备注+协议）
 */
export function buildConfigPage(config, p) {
	const wsPath = (p.path || config.wsPath || '/ws').replace(/^\//, '');
	const cleanPath = `/${wsPath}`;
	const label = p.kind === 'vless' ? 'VLESS' : 'Trojan';
	const legacyPrefix = p.kind === 'vless' ? 'vless' : 'trojan';

	const entries = (Array.isArray(p.entries) && p.entries.length) ? p.entries : null;
	const multi = entries && entries.length > 1;

	// 生成单条节点链接；entry 为 null 时回退请求参数（无入口场景）
	const linkOf = (entry, transport) => {
		const host = entry ? entry.host : p.host;
		const port = entry ? (Number(entry.port) || 443) : (p.port || (p.tls ? 443 : 80));
		const tls = entry ? true : p.tls;
		const wsHost = entry ? (entry.wsHost || entry.host) : p.wsHost;
		const sni = entry ? (entry.sni || wsHost) : p.sni;
		const remark = nodeName(p.kind, transport, entry ? entry.remark : '', `${legacyPrefix}-${transport}`);
		const base = { host, port, wsPath: cleanPath, tls, wsHost, sni };
		return p.kind === 'vless'
			? buildVlessLink({ ...base, uuid: p.credential, transport, remark })
			: buildTrojanLink({ ...base, password: p.credential, transport, remark });
	};

	const rowOf = (entry, transport, idx) => `
  <div class="row">
    <label>${TRANSPORT_NAMES[transport]}</label>
    <div class="linkbox">
      <input type="text" readonly value="${linkOf(entry, transport)}" id="link${idx}">
      <button onclick="copyLink(${idx})">复制</button>
    </div>
  </div>`;

	// 页面分组：无入口 -> 当前域名 + 全协议；有入口 -> 每入口一组（备注 + 勾选协议）
	let groups;
	if (!entries) {
		const transports = (p.transports && p.transports.length) ? p.transports : INBOUND_TRANSPORTS;
		groups = [{ title: '', host: p.host, transports, entry: null }];
	} else {
		groups = entries.map((e) => ({
			title: e.remark || '',
			host: e.host,
			transports: (e.transports && e.transports.length) ? e.transports : INBOUND_TRANSPORTS,
			entry: e,
		}));
	}

	let idx = 0;
	const sections = groups.map((g) => {
		const trans = g.transports.filter((t) => TRANSPORT_NAMES[t]);
		const rows = trans.map((t) => rowOf(g.entry, t, idx++)).join('');
		// 有备注显示备注；无备注回退显示域名（多入口时可区分）
		const head = g.title
			? `<div class="entry-title">${esc(g.title)}</div>`
			: (multi ? `<div class="entry-title">${esc(g.host)}</div>` : '');
		return `${head}${rows}`;
	}).join('');

	const badgeHost = multi ? '多入口' : groups[0].host;
	const transportNames = multi
		? `${groups.length} 个入口，按下方分组复制对应节点`
		: groups[0].transports.filter((t) => TRANSPORT_NAMES[t]).join(' / ');

	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${label} 节点配置</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #f5f5f7; color: #1d1d1f; display: flex; justify-content: center; padding: 48px 16px; margin: 0; }
  .card { background: #fff; border-radius: 16px; padding: 32px; max-width: 640px; width: 100%; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 22px; margin: 0 0 8px; }
  p.desc { color: #6e6e73; font-size: 14px; margin: 0 0 24px; }
  .entry-title { font-size: 15px; font-weight: 600; color: #1d1d1f; margin: 18px 0 10px; padding-top: 14px; border-top: 1px solid #ececf0; }
  .entry-title:first-of-type { border-top: 0; padding-top: 0; margin-top: 0; }
  .row { margin-bottom: 16px; }
  .row label { display: block; font-size: 13px; color: #6e6e73; margin-bottom: 6px; }
  .linkbox { display: flex; gap: 8px; align-items: center; }
  input[type=text] { flex: 1; padding: 10px 12px; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 13px; color: #1d1d1f; background: #fafafa; }
  button { padding: 10px 16px; border: 0; border-radius: 8px; background: #0071e3; color: #fff; font-size: 14px; cursor: pointer; }
  button:hover { background: #0077ed; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; background: #e8f0fe; color: #0071e3; font-size: 12px; font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <h1>${label} 节点 <span class="badge">${esc(badgeHost)}</span></h1>
  <p class="desc">入站路径：<b>${esc(cleanPath)}</b>（当前入口支持：${esc(transportNames) || '无'}，复制链接导入客户端）</p>
  ${sections}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
</script>
</body>
</html>`;
	return html;
}
