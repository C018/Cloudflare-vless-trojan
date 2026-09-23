/**
 * Stream utilities: ws <-> socket bridge
 */

import { WS_READY_STATE_OPEN } from '../config/constants.js';

/**
 * base64 (url-safe) -> ArrayBuffer
 */
export function base64ToArrayBuffer(base64Str) {
	if (!base64Str) return { earlyData: null, error: null };
	try {
		const normalized = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const binary = atob(normalized);
		const buffer = new ArrayBuffer(binary.length);
		const view = new Uint8Array(buffer);
		for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
		return { earlyData: buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

/**
 * 由服务端 WebSocket 构造可读流（支持 0-RTT earlyData）
 */
export function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let canceled = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (canceled) return;
				controller.enqueue(event.data);
			});
			webSocketServer.addEventListener('close', (event) => {
				if (canceled) return;
				log(`ws close code=${event.code}`);
				try { webSocketServer.close(); } catch (e) { /* ignore */ }
				try { controller.close(); } catch (e) { /* ignore */ }
			});
			webSocketServer.addEventListener('error', (err) => {
				try { controller.error(err); } catch (e) { /* ignore */ }
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				try { controller.error(error); } catch (e) { /* ignore */ }
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		cancel() {
			canceled = true;
			try { webSocketServer.close(); } catch (e) { /* ignore */ }
		}
	});
	return stream;
}

export function safeCloseWebSocket(ws) {
	try {
		if (ws && ws.readyState === WS_READY_STATE_OPEN) {
			ws.close();
		}
	} catch (e) { /* ignore */ }
}

/**
 * remote socket/stream -> client ws（首包拼接协议响应头，无数据时触发 retry）
 * @param {Object} remoteSocket {readable, writable?, closed?}
 * @param {WebSocket} webSocket
 * @param {Uint8Array|null} protocolResponseHeader
 * @param {Function|null} retry
 * @param {Function} log
 */
export async function remoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
	let hasIncomingData = false;
	try {
		await remoteSocket.readable.pipeTo(new WritableStream({
			write(chunk) {
				if (webSocket.readyState !== WS_READY_STATE_OPEN) {
					throw new Error('WebSocket is not open');
				}
				hasIncomingData = true;
				if (protocolResponseHeader) {
					const header = new Uint8Array(protocolResponseHeader);
					const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
					const combined = new Uint8Array(header.length + data.length);
					combined.set(header, 0);
					combined.set(data, header.length);
					webSocket.send(combined.buffer);
					protocolResponseHeader = null;
				} else {
					webSocket.send(chunk);
				}
			},
			close() {
				log('remote readable closed');
			},
			abort(reason) {
				log(`remote readable aborted: ${reason}`);
			}
		}));
	} catch (error) {
		log(`remoteSocketToWS error: ${error?.message || error}`);
		safeCloseWebSocket(webSocket);
	}

	if (!hasIncomingData && retry) {
		log('no incoming data, retrying with proxy');
		await retry();
	}
}
