/**
 * Generators: single node links, subscription output (plain / clash / sing-box)
 */

// 0-RTT 参数（?ed=2560）与默认 TLS 指纹（random）
export const ED_PARAM = 'ed=2560';
export const DEFAULT_FINGERPRINT = 'random';

/**
 * 为 ws path 追加 0-RTT 参数（?ed=2560）
 */
export function with0rtt(wsPath) {
	const clean = wsPath.startsWith('/') ? wsPath : `/${wsPath}`;
	if (/\?/.test(clean)) return `${clean}&${ED_PARAM}`;
	return `${clean}?${ED_PARAM}`;
}

/**
 * 生成 vless 节点链接
 * @param {Object} p {uuid, host, port, wsPath, tls, remark, wsHost, sni, fp}
 *  host 为连接地址（入口 IP/域名 或当前域名）；wsHost 为 WebSocket Host 头；sni 为 TLS SNI
 */
export function buildVlessLink(p) {
	const wsPath = with0rtt(p.wsPath);
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const params = new URLSearchParams({
		encryption: 'none',
		type: 'ws',
		path: wsPath,
		host: wsHost,
		security: p.tls ? 'tls' : 'none',
	});
	if (p.tls && sni) params.set('sni', sni);
	if (p.tls) params.set('fp', p.fp || DEFAULT_FINGERPRINT);
	const remark = encodeURIComponent(p.remark || `${p.host}:${p.port}`);
	return `vless://${p.uuid}@${p.host}:${p.port}?${params.toString()}#${remark}`;
}

/**
 * 生成 trojan 节点链接
 */
export function buildTrojanLink(p) {
	const wsPath = with0rtt(p.wsPath);
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const params = new URLSearchParams({
		type: 'ws',
		path: wsPath,
		host: wsHost,
		security: p.tls ? 'tls' : 'none',
	});
	if (p.tls && sni) params.set('sni', sni);
	if (p.tls) params.set('fp', p.fp || DEFAULT_FINGERPRINT);
	const remark = encodeURIComponent(p.remark || `${p.host}:${p.port}`);
	return `trojan://${encodeURIComponent(p.password)}@${p.host}:${p.port}?${params.toString()}#${remark}`;
}

/**
 * 从请求构造 host（优先自定义域名 host 头）
 */
export function resolveHost(request) {
	const hostHeader = request.headers.get('Host');
	if (!hostHeader) return 'example.com';
	return hostHeader.split(':')[0];
}

/**
 * 构建聚合节点列表（vless 多 uuid + trojan 多密码）
 * @param {Object} config
 * @param {Object} p {host, port, tls, wsHost, sni}
 */
export function buildNodeLinks(config, p) {
	const links = [];
	const port = p.port || (p.tls ? 443 : 80);
	for (const u of config.vlessUsers) {
		links.push(buildVlessLink({ uuid: u.uuid, host: p.host, port, wsPath: config.wsPath, tls: p.tls, wsHost: p.wsHost, sni: p.sni, remark: `vless-${u.remark || u.uuid.slice(0, 8)}` }));
	}
	for (const u of config.trojanUsers) {
		links.push(buildTrojanLink({ password: u.password, host: p.host, port, wsPath: config.wsPath, tls: p.tls, wsHost: p.wsHost, sni: p.sni, remark: `trojan-${u.remark || u.password.slice(0, 8)}` }));
	}
	return links;
}

/**
 * 纯文本订阅
 */
export function buildPlainSubscription(config, p) {
	return buildNodeLinks(config, p).join('\n') + '\n';
}

/**
 * Base64 订阅（v2rayN 等）
 */
export function buildBase64Subscription(config, p) {
	return btoa(buildPlainSubscription(config, p));
}

/**
 * Clash YAML 订阅
 */
export function buildClashSubscription(config, p) {
	const port = p.port || 443;
	const tls = p.tls !== false;
	const wsPath = with0rtt(config.wsPath);
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (tls ? wsHost : '');
	const proxies = [];
	const vlessProxies = config.vlessUsers.map((u, i) => ({
		name: `vless-${u.remark || i + 1}`,
		type: 'vless',
		server: p.host,
		port,
		uuid: u.uuid,
		network: 'ws',
		tls,
		'servername': sni || undefined,
		'client-fingerprint': tls ? DEFAULT_FINGERPRINT : undefined,
		'ws-opts': { path: wsPath, headers: { Host: wsHost } },
		udp: true
	}));
	const trojanProxies = config.trojanUsers.map((u, i) => ({
		name: `trojan-${u.remark || i + 1}`,
		type: 'trojan',
		server: p.host,
		port,
		password: u.password,
		network: 'ws',
		tls,
		'servername': sni || undefined,
		'client-fingerprint': tls ? DEFAULT_FINGERPRINT : undefined,
		'ws-opts': { path: wsPath, headers: { Host: wsHost } },
		udp: true
	}));
	proxies.push(...vlessProxies, ...trojanProxies);

	const lines = ['proxies:'];
	for (const pr of proxies) {
		lines.push(`  - name: "${pr.name}"`);
		lines.push(`    type: ${pr.type}`);
		lines.push(`    server: ${pr.server}`);
		lines.push(`    port: ${pr.port}`);
		if (pr.uuid) lines.push(`    uuid: ${pr.uuid}`);
		if (pr.password) lines.push(`    password: "${pr.password}"`);
		lines.push(`    network: ws`);
		lines.push(`    tls: ${pr.tls}`);
		if (pr['servername']) lines.push(`    servername: ${pr['servername']}`);
		if (pr['client-fingerprint']) lines.push(`    client-fingerprint: ${pr['client-fingerprint']}`);
		lines.push(`    udp: true`);
		lines.push(`    ws-opts:`);
		lines.push(`      path: ${pr['ws-opts'].path}`);
		lines.push(`      headers:`);
		lines.push(`        Host: ${wsHost}`);
	}
	lines.push('');
	lines.push('rules:');
	lines.push('  - MATCH,DIRECT');
	return lines.join('\n');
}

/**
 * sing-box JSON 订阅
 */
export function buildSingBoxSubscription(config, p) {
	const port = p.port || 443;
	const wsPath = with0rtt(config.wsPath);
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const outbounds = [];
	for (const u of config.vlessUsers) {
		outbounds.push({
			type: 'vless',
			tag: `vless-${u.remark || u.uuid.slice(0, 8)}`,
			server: p.host,
			server_port: port,
			uuid: u.uuid,
			transport: { type: 'ws', path: wsPath, headers: { Host: wsHost } },
			tls: p.tls ? { enabled: true, server_name: sni, fingerprint: DEFAULT_FINGERPRINT } : null,
		});
	}
	for (const u of config.trojanUsers) {
		outbounds.push({
			type: 'trojan',
			tag: `trojan-${u.remark || u.password.slice(0, 8)}`,
			server: p.host,
			server_port: port,
			password: u.password,
			transport: { type: 'ws', path: wsPath, headers: { Host: wsHost } },
			tls: p.tls ? { enabled: true, server_name: sni, fingerprint: DEFAULT_FINGERPRINT } : null,
		});
	}
	return JSON.stringify({ outbounds, log: { level: 'info' } }, null, 2);
}
