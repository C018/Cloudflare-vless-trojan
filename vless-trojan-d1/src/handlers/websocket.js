/**
 * WebSocket inbound handler: VLESS / Trojan protocol dispatch
 * 仅负责 WebSocket 升级与 ws 消息 ↔ 字节流适配，代理核心逻辑在 proxy-session.js
 */

import { processProxySession } from './proxy-session.js';
import { safeCloseWebSocket } from '../outbound/stream.js';

/**
 * 将 ws 消息统一归一化为 Uint8Array（支持 ArrayBuffer / 视图 / 文本帧）
 */
function normalizeToUint8Array(data) {
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return new TextEncoder().encode(data);
	return null;
}

/**
 * 处理 WebSocket 升级请求（代理入口）
 */
export async function handleWebSocketUpgrade(request, config, env) {
	const upgrade = request.headers.get('Upgrade');
	if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
		return new Response('Expected WebSocket', { status: 400 });
	}
	const [client, server] = Object.values(new WebSocketPair());
	server.accept();

	const log = (...args) => console.log('[ws]', ...args);
	processProxySession(config, env, log, createWsIO(server, log)).catch((e) => {
		log(`ws handler error: ${e.message || e}`);
		safeCloseWebSocket(server);
	});

	return new Response(null, { status: 101, webSocket: client });
}

/**
 * 将 WebSocket 适配为 io 接口（读=ws 消息，写=ws.send，关=safeClose）
 */
function createWsIO(ws, log) {
	const queue = [];
	const waiters = [];
	let eof = false;

	const onMessage = (event) => {
		const data = normalizeToUint8Array(event.data);
		if (!data || data.byteLength === 0) return;
		const waiter = waiters.shift();
		if (waiter) waiter(data);
		else queue.push(data);
	};
	const onClose = () => {
		if (eof) return;
		eof = true;
		while (waiters.length) waiters.shift()(null);
	};
	const onError = () => onClose();

	ws.addEventListener('message', onMessage);
	ws.addEventListener('close', onClose);
	ws.addEventListener('error', onError);

	return {
		read() {
			if (queue.length) return Promise.resolve(queue.shift());
			if (eof) return Promise.resolve(null);
			return new Promise((resolve) => waiters.push(resolve));
		},
		write(data) {
			if (ws.readyState === 1) {
				try { ws.send(data); } catch (e) { /* ignore */ }
			}
		},
		close() {
			safeCloseWebSocket(ws);
		}
	};
}
