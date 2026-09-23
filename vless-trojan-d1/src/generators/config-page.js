/**
 * Single-node config page generator
 */

import { buildVlessLink, buildTrojanLink } from './subscription.js';

/**
 * /{uuid|password} 页面：展示该凭据对应的节点链接
 * @param {Object} config
 * @param {Object} p {host, port, tls, credential, kind}
 */
export function buildConfigPage(config, p) {
	const host = p.host;
	const port = p.port || (p.tls ? 443 : 80);
	const wsPath = config.wsPath.startsWith('/') ? config.wsPath : `/${config.wsPath}`;

	let link = '';
	let label = '';
	if (p.kind === 'vless') {
		link = buildVlessLink({ uuid: p.credential, host, port, wsPath, tls: p.tls, remark: 'vless-node' });
		label = 'VLESS';
	} else if (p.kind === 'trojan') {
		link = buildTrojanLink({ password: p.credential, host, port, wsPath, tls: p.tls, remark: 'trojan-node' });
		label = 'Trojan';
	}

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
  <p class="desc">复制下方链接到 v2rayN / sing-box / Clash 客户端导入节点</p>
  <div class="row">
    <label>节点分享链接</label>
    <div class="linkbox">
      <input type="text" readonly value="${link}" id="link">
      <button onclick="copyLink()">复制</button>
    </div>
  </div>
</div>
<script>
function copyLink(){ const el=document.getElementById('link'); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
</script>
</body>
</html>`;
	return html;
}
