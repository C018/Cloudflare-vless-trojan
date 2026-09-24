/**
 * Single-node config page generator
 * 入站已支持全类型自动（ws/grpc/h2 共享同一入站路径），页面展示三种传输的节点链接。
 */

import { buildVlessLink, buildTrojanLink } from './subscription.js';

/**
 * /{uuid|password} 页面：展示该凭据对应的节点链接（ws / grpc / h2）
 * @param {Object} config
 * @param {Object} p {host, port, tls, wsHost, sni, credential, kind, path}
 */
export function buildConfigPage(config, p) {
	const host = p.host;
	const port = p.port || (p.tls ? 443 : 80);
	const wsPath = (p.path || config.wsPath || '/ws').replace(/^\//, '');
	const cleanPath = `/${wsPath}`;

	const base = { host, port, wsPath: cleanPath, tls: p.tls, wsHost: p.wsHost, sni: p.sni };
	const linkOf = (transport, remark) => {
		if (p.kind === 'vless') {
			return buildVlessLink({ ...base, uuid: p.credential, transport, remark: `vless-${remark}` });
		}
		return buildTrojanLink({ ...base, password: p.credential, transport, remark: `trojan-${remark}` });
	};

	const links = [
		{ name: 'WebSocket (ws)', link: linkOf('ws', 'ws') },
		{ name: 'gRPC', link: linkOf('grpc', 'grpc') },
		{ name: 'HTTP/2 (h2)', link: linkOf('h2', 'h2') },
	];

	const label = p.kind === 'vless' ? 'VLESS' : 'Trojan';
	const rows = links.map((l, i) => `
  <div class="row">
    <label>${l.name}</label>
    <div class="linkbox">
      <input type="text" readonly value="${l.link}" id="link${i}">
      <button onclick="copyLink(${i})">复制</button>
    </div>
  </div>`).join('');

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
  <h1>${label} 节点 <span class="badge">${host}</span></h1>
  <p class="desc">入站路径：<b>${cleanPath}</b>（服务端已自动兼容 ws / grpc / h2，复制任一链接导入客户端）</p>
  ${rows}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
</script>
</body>
</html>`;
	return html;
}
