/**
 * Generators: single node links, subscription output (plain / clash / sing-box)
 * 入站传输模式（config.entryTransport: ws / grpc / h2）决定链接/配置的 network 与 path/serviceName。
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

/** 取 serviceName（grpc 用）：wsPath 去首尾斜杠，如 /ws -> ws */
function serviceNameOf(wsPath) {
	return (wsPath.startsWith('/') ? wsPath : `/${wsPath}`).replace(/\/+$/, '').replace(/^\//, '');
}

/**
 * 生成 vless 节点链接
 * @param {Object} p {uuid, host, port, wsPath, tls, remark, wsHost, sni, fp, transport}
 *  host 为连接地址（入口 IP/域名 或当前域名）；wsHost 为 WebSocket Host 头；sni 为 TLS SNI
 */
export function buildVlessLink(p) {
	const transport = p.transport || 'ws';
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const params = new URLSearchParams({
		encryption: 'none',
		type: transport,
		host: wsHost,
		security: p.tls ? 'tls' : 'none',
	});
	if (transport === 'grpc') {
		params.set('serviceName', `/${serviceNameOf(p.wsPath)}`);
	} else {
		params.set('path', with0rtt(p.wsPath));
	}
	if (p.tls && sni) params.set('sni', sni);
	if (p.tls) params.set('fp', p.fp || DEFAULT_FINGERPRINT);
	const remark = encodeURIComponent(p.remark || `${p.host}:${p.port}`);
	return `vless://${p.uuid}@${p.host}:${p.port}?${params.toString()}#${remark}`;
}

/**
 * 生成 trojan 节点链接
 */
export function buildTrojanLink(p) {
	const transport = p.transport || 'ws';
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const params = new URLSearchParams({
		type: transport,
		host: wsHost,
		security: p.tls ? 'tls' : 'none',
	});
	if (transport === 'grpc') {
		params.set('serviceName', `/${serviceNameOf(p.wsPath)}`);
	} else {
		params.set('path', with0rtt(p.wsPath));
	}
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
 * 入站已支持全类型自动（ws/grpc/h2），每个用户输出三种传输节点；
 * 每个用户优先使用其自定义入站路径（u.path），未设置时回退全局 config.wsPath。
 * @param {Object} config
 * @param {Object} p {host, port, tls, wsHost, sni}
 */
export const INBOUND_TRANSPORTS = ['ws', 'grpc', 'h2'];

export function buildNodeLinks(config, p) {
	const links = [];
	const port = p.port || (p.tls ? 443 : 80);
	for (const u of config.vlessUsers) {
		const wsPath = u.path || config.wsPath;
		for (const transport of INBOUND_TRANSPORTS) {
			links.push(buildVlessLink({ uuid: u.uuid, host: p.host, port, wsPath, tls: p.tls, wsHost: p.wsHost, sni: p.sni, transport, remark: `vless-${u.remark || u.uuid.slice(0, 8)}-${transport}` }));
		}
	}
	for (const u of config.trojanUsers) {
		const wsPath = u.path || config.wsPath;
		for (const transport of INBOUND_TRANSPORTS) {
			links.push(buildTrojanLink({ password: u.password, host: p.host, port, wsPath, tls: p.tls, wsHost: p.wsHost, sni: p.sni, transport, remark: `trojan-${u.remark || u.password.slice(0, 8)}-${transport}` }));
		}
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
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (tls ? wsHost : '');
	const proxies = [];

	const clashProxy = (name, type, credKey, cred, wsPath, transport) => {
		const pr = {
			name,
			type,
			server: p.host,
			port,
			[credKey]: cred,
			network: transport,
			tls,
			'servername': sni || undefined,
			'client-fingerprint': tls ? DEFAULT_FINGERPRINT : undefined,
			udp: true
		};
		if (transport === 'grpc') {
			pr['grpc-opts'] = { 'grpc-service-name': `/${serviceNameOf(wsPath)}` };
		} else if (transport === 'h2') {
			pr['h2-opts'] = { path: with0rtt(wsPath), host: [wsHost] };
		} else {
			pr['ws-opts'] = { path: with0rtt(wsPath), headers: { Host: wsHost } };
		}
		return pr;
	};

	config.vlessUsers.forEach((u, i) => {
		for (const transport of INBOUND_TRANSPORTS) {
			proxies.push(clashProxy(`vless-${u.remark || i + 1}-${transport}`, 'vless', 'uuid', u.uuid, u.path || config.wsPath, transport));
		}
	});
	config.trojanUsers.forEach((u, i) => {
		for (const transport of INBOUND_TRANSPORTS) {
			proxies.push(clashProxy(`trojan-${u.remark || i + 1}-${transport}`, 'trojan', 'password', u.password, u.path || config.wsPath, transport));
		}
	});

	const lines = ['proxies:'];
	for (const pr of proxies) {
		lines.push(`  - name: "${pr.name}"`);
		lines.push(`    type: ${pr.type}`);
		lines.push(`    server: ${pr.server}`);
		lines.push(`    port: ${pr.port}`);
		if (pr.uuid) lines.push(`    uuid: ${pr.uuid}`);
		if (pr.password) lines.push(`    password: "${pr.password}"`);
		lines.push(`    network: ${pr.network}`);
		lines.push(`    tls: ${pr.tls}`);
		if (pr['servername']) lines.push(`    servername: ${pr['servername']}`);
		if (pr['client-fingerprint']) lines.push(`    client-fingerprint: ${pr['client-fingerprint']}`);
		lines.push(`    udp: true`);
		if (pr.network === 'grpc') {
			lines.push(`    grpc-opts:`);
			lines.push(`      grpc-service-name: ${pr['grpc-opts']['grpc-service-name']}`);
		} else if (pr.network === 'h2') {
			lines.push(`    h2-opts:`);
			lines.push(`      path: ${pr['h2-opts'].path}`);
			lines.push(`      host:`);
			lines.push(`        - ${wsHost}`);
		} else {
			lines.push(`    ws-opts:`);
			lines.push(`      path: ${pr['ws-opts'].path}`);
			lines.push(`      headers:`);
			lines.push(`        Host: ${wsHost}`);
		}
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
	const wsHost = p.wsHost || p.host;
	const sni = p.sni || (p.tls ? wsHost : '');
	const outbounds = [];
	const transportOf = (wsPath, transport) => {
		if (transport === 'grpc') {
			return { type: 'grpc', service_name: `/${serviceNameOf(wsPath)}` };
		}
		if (transport === 'h2') {
			return { type: 'http', host: [wsHost], path: with0rtt(wsPath) };
		}
		return { type: 'ws', path: with0rtt(wsPath), headers: { Host: wsHost } };
	};
	for (const u of config.vlessUsers) {
		for (const transport of INBOUND_TRANSPORTS) {
			outbounds.push({
				type: 'vless',
				tag: `vless-${u.remark || u.uuid.slice(0, 8)}-${transport}`,
				server: p.host,
				server_port: port,
				uuid: u.uuid,
				transport: transportOf(u.path || config.wsPath, transport),
				tls: p.tls ? { enabled: true, server_name: sni, fingerprint: DEFAULT_FINGERPRINT } : null,
			});
		}
	}
	for (const u of config.trojanUsers) {
		for (const transport of INBOUND_TRANSPORTS) {
			outbounds.push({
				type: 'trojan',
				tag: `trojan-${u.remark || u.password.slice(0, 8)}-${transport}`,
				server: p.host,
				server_port: port,
				password: u.password,
				transport: transportOf(u.path || config.wsPath, transport),
				tls: p.tls ? { enabled: true, server_name: sni, fingerprint: DEFAULT_FINGERPRINT } : null,
			});
		}
	}
	return JSON.stringify({ outbounds, log: { level: 'info' } }, null, 2);
}
