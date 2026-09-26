/**
 * Durable Object: 长连接代理会话（ProxySessionDO）
 *
 * 目的：将 WebSocket 代理入站会话托管到 DO，突破 Workers 无状态请求
 * 30s idle 断连限制，Telegram 等长连接不再「正在刷新」。
 *
 * 设计（标准模式，非 Hibernation 事件驱动）：
 * - fetch 内校验 Upgrade → state.acceptWebSocket 接管握手，立即返回 101；
 * - processProxySession 作为后台任务持续运行（io.read 挂起等帧）；
 * - DO 因存在活跃 WebSocket 连接而保持实例存活，会话期间不被 idle 回收；
 * - ws 关闭后 createWsIO 置 eof、会话自然结束，实例释放。
 *
 * 部署（dashboard 手动路线 B）：
 * - Settings → Bindings → Durable Objects：Add binding
 *   variable name = PROXY_DO，class name = ProxySessionDO
 * - 同页添加 migration：new_sqlite_classes 加入 ProxySessionDO
 * - 保存后粘贴构建产物 _worker.js（入口已 re-export 本 class）
 */

import { connect } from 'cloudflare:sockets';
import { createRequestConfig, composeInboundScope } from '../config/defaults.js';
import { processProxySession } from '../handlers/proxy-session.js';
import { extractEarlyData, createWsIO } from '../handlers/websocket.js';
import { safeCloseWebSocket } from '../outbound/stream.js';

// 与 index.js 一致的平台 Socket 建连能力注入（幂等，bundle 顶层执行）
globalThis.connect = connect;

export class ProxySessionDO {
	constructor(state, env) {
		this.state = state;
		this.env = env;
	}

	/**
	 * 代理入站握手：仅接受 Upgrade: websocket 请求（grpc/h2 仍走 Worker 内处理）
	 */
	async fetch(request) {
		const upgrade = request.headers.get('Upgrade');
		if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
			return new Response('Expected WebSocket', { status: 400 });
		}

		const log = (...args) => console.log('[ws-do]', ...args);
		const config = await createRequestConfig(request, this.env);
		const path = new URL(request.url).pathname;
		const scopes = config.inboundPathMap.get(path);
		if (!scopes || scopes.length === 0) {
			return new Response('Not Found', { status: 404 });
		}
		config._inboundScope = composeInboundScope(scopes);

		const [client, server] = Object.values(new WebSocketPair());
		this.state.acceptWebSocket(server);

		// acceptWebSocket 同步返回后、会话启动前注入 early data（若有）
		const earlyData = extractEarlyData(request, log);
		processProxySession(config, this.env, log, createWsIO(server, log, earlyData)).catch((e) => {
			log(`ws session error: ${e.message || e}`);
			safeCloseWebSocket(server);
		});

		return new Response(null, { status: 101, webSocket: client });
	}
}
