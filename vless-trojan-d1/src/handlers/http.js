/**
 * HTTP handlers: config page, subscription endpoints, disguise page
 */

import { resolveHost, buildVlessLink, buildTrojanLink, buildPlainSubscription, buildBase64Subscription, buildClashSubscription, buildSingBoxSubscription } from '../generators/subscription.js';
import { buildConfigPage } from '../generators/config-page.js';
import { buildDisguisePage } from '../disguise/alist.js';

function html(content, status = 200) {
	return new Response(content, {
		status,
		headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
	});
}

function text(content, contentType = 'text/plain; charset=utf-8') {
	return new Response(content, { headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store' } });
}

/**
 * 订阅入口
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Object} config
 * @param {Object} opts {host, tls, port}
 */
function serveSubscription(request, config, opts) {
	const url = new URL(request.url);
	const format = (url.searchParams.get('format') || 'base64').toLowerCase();
	const includePreferred = url.searchParams.get('preferred') !== '0';
	const p = { host: opts.host, port: opts.port, tls: opts.tls, includePreferred };

	switch (format) {
		case 'plain':
			return text(buildPlainSubscription(config, p));
		case 'clash':
		case 'yaml':
			return text(buildClashSubscription(config, p), 'text/yaml; charset=utf-8');
		case 'singbox':
		case 'sing-box':
		case 'json':
			return text(buildSingBoxSubscription(config, p), 'application/json; charset=utf-8');
		case 'base64':
		default:
			return text(buildBase64Subscription(config, p));
	}
}

/**
 * 单凭据订阅（校验 uuid/password）
 */
function serveCredentialSubscription(request, config, credential, opts) {
	const url = new URL(request.url);
	let matched = null;
	if (config.uuidSet.has(credential)) {
		matched = { kind: 'vless', user: config.vlessIndex[credential] };
	} else if (config.passwordSet.has(credential)) {
		matched = { kind: 'trojan', user: config.trojanIndex[credential] };
	}
	if (!matched) return new Response('Not Found', { status: 404 });

	const format = (url.searchParams.get('format') || 'base64').toLowerCase();
	const host = opts.host;
	const port = opts.port;
	const wsPath = config.wsPath;

	let link;
	if (matched.kind === 'vless') {
		link = buildVlessLink({ uuid: matched.user.uuid, host, port, wsPath: config.wsPath, tls: opts.tls, remark: `vless-${matched.user.remark || 'node'}` });
	} else {
		link = buildTrojanLink({ password: matched.user.password, host, port, wsPath: config.wsPath, tls: opts.tls, remark: `trojan-${matched.user.remark || 'node'}` });
	}
	if (format === 'plain') return text(link + '\n');
	return text(btoa(link + '\n'));
}

/**
 * HTTP 路由入口（非 ws / 非 admin / 非 cron）
 */
export async function handleHttp(request, config, env) {
	const url = new URL(request.url);
	const path = url.pathname;
	const host = resolveHost(request);
	const tls = url.protocol === 'https:';
	const port = Number(url.port) || (tls ? 443 : 80);
	const opts = { host, tls, port };

	// 订阅端点
	if (path === '/subscribe') {
		return serveSubscription(request, config, opts);
	}

	// /{credential}/subscribe
	const credSubMatch = path.match(/^\/([^/]+)\/subscribe$/);
	if (credSubMatch) {
		return serveCredentialSubscription(request, config, decodeURIComponent(credSubMatch[1]), opts);
	}

	// /{credential} 单节点配置页
	const credMatch = path.match(/^\/([^/]+)$/);
	if (credMatch) {
		const credential = decodeURIComponent(credMatch[1]);
		if (config.uuidSet.has(credential)) {
			return html(buildConfigPage(config, { host, port, tls, credential, kind: 'vless' }));
		}
		if (config.passwordSet.has(credential)) {
			return html(buildConfigPage(config, { host, port, tls, credential, kind: 'trojan' }));
		}
	}

	// 兜底：Alist 伪装页
	return html(buildDisguisePage(config.settings));
}
