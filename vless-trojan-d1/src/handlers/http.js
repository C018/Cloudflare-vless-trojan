/**
 * HTTP handlers: config page, subscription endpoints, disguise page
 */

import { resolveHost, buildVlessLink, buildTrojanLink, INBOUND_TRANSPORTS, buildPlainSubscription, buildBase64Subscription, buildClashSubscription, buildSingBoxSubscription } from '../generators/subscription.js';
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
 * @param {Array} targets 目标入口数组，每项 {host, port, tls, wsHost, sni, transports, name}
 */
function serveSubscription(request, config, targets) {
	const url = new URL(request.url);
	const format = (url.searchParams.get('format') || 'base64').toLowerCase();

	switch (format) {
		case 'plain':
			return text(buildPlainSubscription(config, targets));
		case 'clash':
		case 'yaml':
			return text(buildClashSubscription(config, targets), 'text/yaml; charset=utf-8');
		case 'singbox':
		case 'sing-box':
		case 'json':
			return text(buildSingBoxSubscription(config, targets), 'application/json; charset=utf-8');
		case 'base64':
		default:
			return text(buildBase64Subscription(config, targets));
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
	const wsPath = matched.user.path || config.wsPath;
	// 仅输出当前入口支持的协议（未匹配入口时默认全协议）
	const transports = (opts.transports && opts.transports.length) ? opts.transports : INBOUND_TRANSPORTS;

	const links = [];
	for (const transport of transports) {
		if (matched.kind === 'vless') {
			links.push(buildVlessLink({ uuid: matched.user.uuid, host, port, wsPath, tls: opts.tls, wsHost: opts.wsHost, sni: opts.sni, transport, remark: `vless-${matched.user.remark || 'node'}-${transport}` }));
		} else {
			links.push(buildTrojanLink({ password: matched.user.password, host, port, wsPath, tls: opts.tls, wsHost: opts.wsHost, sni: opts.sni, transport, remark: `trojan-${matched.user.remark || 'node'}-${transport}` }));
		}
	}
	const body = links.join('\n') + '\n';
	if (format === 'plain') return text(body);
	return text(btoa(body));
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
	// 入口匹配：请求 Host 命中某入口（host 或 wsHost）时，该入口作为"当前入口"
	const requestHost = host.toLowerCase().replace(/:\d+$/, '');
	const matchEntry = (e) => {
		const hs = [e.host, e.wsHost].filter(Boolean).map((h) => h.toLowerCase().replace(/:\d+$/, ''));
		return hs.some((h) => h === requestHost);
	};
	const matched = config.entries.find(matchEntry);
	// 单凭据页/单凭据订阅：命中入口时仅输出该入口勾选的协议，否则按当前域名全协议
	const singleOpts = matched
		? {
			host: matched.host,
			port: Number(matched.port) || 443,
			tls: true,
			wsHost: matched.wsHost,
			sni: matched.sni,
			transports: matched.transports,
		}
		: { host, port, tls, wsHost: host, sni: host };
	// 聚合订阅：命中入口 -> 仅该入口（含勾选协议）；未命中但有入口设置 -> 聚合全部入口；
	// 无入口设置 -> 当前域名 + 全协议（保持原行为）
	let targets;
	if (matched) {
		targets = [{
			host: matched.host,
			port: Number(matched.port) || 443,
			tls: true,
			wsHost: matched.wsHost,
			sni: matched.sni,
			transports: matched.transports,
			name: matched.remark || matched.host,
		}];
	} else if (config.entries.length) {
		targets = config.entries.map((e) => ({
			host: e.host,
			port: Number(e.port) || 443,
			tls: true,
			wsHost: e.wsHost,
			sni: e.sni,
			transports: e.transports,
			name: e.remark || e.host,
		}));
	} else {
		targets = [{ host, port, tls, wsHost: host, sni: host }];
	}

	// 订阅端点
	if (path === '/subscribe') {
		return serveSubscription(request, config, targets);
	}

	// /{credential}/subscribe
	const credSubMatch = path.match(/^\/([^/]+)\/subscribe$/);
	if (credSubMatch) {
		return serveCredentialSubscription(request, config, decodeURIComponent(credSubMatch[1]), singleOpts);
	}

	// /{credential} 单节点配置页
	const credMatch = path.match(/^\/([^/]+)$/);
	if (credMatch) {
		const credential = decodeURIComponent(credMatch[1]);
		if (config.uuidSet.has(credential)) {
			const user = config.vlessIndex[credential];
			return html(buildConfigPage(config, { host: singleOpts.host, port: singleOpts.port, tls: singleOpts.tls, wsHost: singleOpts.wsHost, sni: singleOpts.sni, transports: singleOpts.transports, credential, kind: 'vless', path: (user && user.path) || config.wsPath }));
		}
		if (config.passwordSet.has(credential)) {
			const user = config.trojanIndex[credential];
			return html(buildConfigPage(config, { host: singleOpts.host, port: singleOpts.port, tls: singleOpts.tls, wsHost: singleOpts.wsHost, sni: singleOpts.sni, transports: singleOpts.transports, credential, kind: 'trojan', path: (user && user.path) || config.wsPath }));
		}
	}

	// 兜底：Alist 伪装页
	return html(buildDisguisePage(config.settings));
}
