/**
 * Durable Object: 长连接代理会话（ProxySessionDO）
 *
 * 目的：将 WebSocket 代理入站会话托管到 DO，突破 Workers 无状态请求
 * 30s idle 断连限制，Telegram 等长连接不再「正在刷新」。
 *
 * 设计（Hibernation API + 会话后台循环）：
 * - fetch 内校验 Upgrade → state.acceptWebSocket 接管握手，立即返回 101；
 * - 关键：DO 内 WS 消息必须通过 Hibernation API 的 webSocketMessage 类方法接收，
 *   平台不会把事件投递给 addEventListener（官方文档明确：
 *   "The WebSocket Hibernation API takes the place of the standard WebSockets API.
 *   ws.addEventListener method will not receive events as they will instead be
 *   delivered to the Durable Object"）。
 *   webSocketMessage 将归一化字节注入会话 io 队列（feed），供 io.read 消费；
 * - processProxySession 作为后台任务持续运行（io.read 挂起等帧），
 *   出站 TCP/UDP 转发与流量统计逻辑与 Worker 内路径完全一致；
 * - webSocketClose / webSocketError 置 io EOF，会话自然结束，实例释放。
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
		this.io = null;
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
		this.io = createWsIO(server, log, earlyData);
		processProxySession(config, this.env, log, this.io).catch((e) => {
			log(`ws session error: ${e.message || e}`);
			// [DIAG] 记录会话异常到 D1：按 60s 时间窗口限频（高频异常场景只写 1 条/窗口），
			// 保留排障价值的同时降低 diag_log 表写入频率
			try {
				const nowTs = Date.now();
				if (nowTs - (this._lastDiagTs || 0) >= 60_000) {
					this._lastDiagTs = nowTs;
					const msg = String((e && e.stack) || e).slice(0, 400);
					this.env.DB.prepare('INSERT INTO diag_log (ts, tag, result) VALUES (?, ?, ?)').bind(nowTs, 'session_error', msg).run();
				}
			} catch (err) { /* ignore */ }
			safeCloseWebSocket(server);
		});

		return new Response(null, { status: 101, webSocket: client });
	}

	/**
	 * Hibernation API：客户端 WS 消息统一在此接收并注入 io 队列
	 * （DO 中 addEventListener('message') 不生效，平台只投递本方法）
	 */
	async webSocketMessage(ws, message) {
		if (!this.io) return;
		let bytes = null;
		if (message instanceof ArrayBuffer) {
			bytes = new Uint8Array(message);
		} else if (ArrayBuffer.isView(message)) {
			bytes = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
		} else if (typeof message === 'string') {
			bytes = new TextEncoder().encode(message);
		}
		if (!bytes || bytes.byteLength === 0) return;
		// 注意：此处禁止每帧打日志——大流量下载时每帧 console.log 会同步拖慢 DO 事件循环，严重拉低吞吐
		this.io.feed(bytes);
	}

	/** Hibernation API：连接关闭 → io EOF（正常关闭不打日志，仅异常 code 记录） */
	async webSocketClose(ws, code, reason, wasClean) {
		if (code !== 1000 && code !== 1001) {
			console.log(`[ws-do] webSocketClose code=${code} wasClean=${wasClean}`);
		}
		if (this.io) this.io.signalClose();
	}

	/** Hibernation API：连接异常 → io EOF（按 60s 窗口限频，避免客户端反复异常断开刷屏） */
	async webSocketError(ws, error) {
		const nowTs = Date.now();
		if (nowTs - (this._lastWSErrTs || 0) >= 60_000) {
			this._lastWSErrTs = nowTs;
			console.log(`[ws-do] webSocketError ${(error && error.message) || error}`);
		}
		if (this.io) this.io.signalClose();
	}
}
