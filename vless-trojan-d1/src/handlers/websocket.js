/**
 * WebSocket inbound handler: VLESS / Trojan protocol dispatch
 * 仅负责 WebSocket 升级与 ws 消息 ↔ 字节流适配，代理核心逻辑在 proxy-session.js
 *
 * WS early data（0-RTT）支持：
 * - xray 客户端在 VLESS 链接带 ?ed=2560 时，会把首个数据包 base64 编码后放入
 *   Sec-WebSocket-Protocol 头；CF Workers 平台无法读取 Upgrade request body，
 *   因此采用与 EDtunnel 相同的 Sec-WebSocket-Protocol base64 通道。
 * - 解析出的 early data 在 server.accept() 同步返回后、processProxySession 启动前
 *   注入读取队列，作为首包参与 VLESS/Trojan 协议解析，消除"客户端首包在头里、
 *   服务端只等 ws message 帧"的双向死锁。
 */

import { processProxySession } from './proxy-session.js';
import { safeCloseWebSocket, base64ToArrayBuffer } from '../outbound/stream.js';

// write() 必须返回 Promise（调用方存在 .catch 链）；复用同一 resolved Promise 避免每帧分配
const RESOLVED = Promise.resolve();

/**
 * 将 ws 消息统一归一化为 Uint8Array（支持 ArrayBuffer / 视图 / 文本帧 / 跨 realm ArrayBuffer）
 * Blob 需异步转换，由调用方先 await arrayBuffer() 再传入。
 */
function normalizeToUint8Array(data) {
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return new TextEncoder().encode(data);
	// 跨 realm ArrayBuffer：平台内部构造的 ArrayBuffer 可能不满足 instanceof
	if (Object.prototype.toString.call(data) === '[object ArrayBuffer]') return new Uint8Array(data);
	return null;
}

/**
 * 提取 WS early data：
 * 1) 解析 URL ?ed= 参数（xray 宣告的 early data 上限，用于日志/校验）；
 * 2) 从 Sec-WebSocket-Protocol 头提取 base64 数据（兼容 "base64," 前缀），
 *    这是 xray ed=2560 场景下 early data 的实际传输通道。
 * @param {Request} request
 * @param {Function} log
 * @returns {Uint8Array|null}
 */
export function extractEarlyData(request, log) {
	const edParam = new URL(request.url).searchParams.get('ed');
	// 降噪：ed=2560 是 xray 客户端标准声明，正常 0-RTT 连接不打注入/无负载日志；
	// 仅当 ed 参数缺失或非预期值时保留日志（异常/兼容性排障有价值）
	const quietEd = edParam === '2560';
	let header = request.headers.get('sec-websocket-protocol') || '';
	if (header) {
		if (header.startsWith('base64,')) header = header.slice(7);
		const { earlyData, error } = base64ToArrayBuffer(header);
		if (error) {
			log(`early data decode error: ${error.message || error}`);
			return null;
		}
		if (earlyData && earlyData.byteLength > 0) {
			if (!quietEd) log(`early data injected: ${earlyData.byteLength} B (ed=${edParam || 'n/a'})`);
			return new Uint8Array(earlyData);
		}
	}
	if (edParam && !quietEd) {
		log(`ed=${edParam} declared but no sec-websocket-protocol payload`);
	}
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
	// accept() 同步返回后、processProxySession 启动前注入 early data（若有）
	const earlyData = extractEarlyData(request, log);
	processProxySession(config, env, log, createWsIO(server, log, earlyData)).catch((e) => {
		log(`ws handler error: ${e.message || e}`);
		safeCloseWebSocket(server);
	});

	return new Response(null, { status: 101, webSocket: client });
}

/**
 * 将 WebSocket 适配为 io 接口（读=ws 消息，写=ws.send，关=safeClose）
 * @param {WebSocket} ws
 * @param {Function} log
 * @param {Uint8Array|null} earlyData 首个数据块（early data），先于 ws message 入队
 */
export function createWsIO(ws, log, earlyData = null) {
	const queue = [];
	const waiters = [];
	let eof = false;

	if (earlyData && earlyData.byteLength > 0) {
		queue.push(earlyData);
	} else {
		// 非 0-RTT：首包必须来自 message 事件。设 6s 兜底，避免平台丢帧/客户端不发导致永久挂起（hung）
		setTimeout(() => {
			if (!eof && queue.length === 0 && waiters.length > 0) {
				log('first packet timeout: no ws message within 6s');
				safeCloseWebSocket(ws);
			}
		}, 6000);
	}

	const onMessage = async (event) => {
		// Blob 帧需先异步转 ArrayBuffer
		let data = event.data;
		if (typeof Blob !== 'undefined' && data instanceof Blob) {
			data = await data.arrayBuffer();
		}
		const bytes = normalizeToUint8Array(data);
		if (!bytes || bytes.byteLength === 0) {
			log(`message dropped: type=${Object.prototype.toString.call(event.data)} len=${data && data.byteLength != null ? data.byteLength : data && data.length != null ? data.length : 'n/a'}`);
			return;
		}
		const waiter = waiters.shift();
		if (waiter) waiter(bytes);
		else queue.push(bytes);
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
			// 复用共享 resolved Promise：调用方存在 io.write(...).catch() 链，
			// 无返回值会抛 "Cannot read properties of undefined (reading 'catch')"
			return RESOLVED;
		},
		close() {
			safeCloseWebSocket(ws);
		},
		/**
		 * Hibernation API 注入：DO 内 addEventListener('message') 不生效，
		 * webSocketMessage 类方法收到的帧必须经此进入读取队列。
		 */
		feed(bytes) {
			if (!bytes || bytes.byteLength === 0) return;
			const waiter = waiters.shift();
			if (waiter) waiter(bytes);
			else queue.push(bytes);
		},
		/**
		 * Hibernation API 注入：webSocketClose / webSocketError 时置 EOF。
		 */
		signalClose() {
			onClose();
		}
	};
}
