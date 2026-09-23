/**
 * VLESS outbound transport: httpupgrade
 * 通过 HTTP Upgrade 机制建连：TCP（可选 TLS）建连后发送
 * `GET {path} HTTP/1.1 + Connection: Upgrade + Upgrade: websocket` 握手，
 * 服务器返回 101 Switching Protocols 后即视为裸双向流，直接承载 VLESS 数据。
 */

const HANDSHAKE_TIMEOUT = 10000;

function concatBytes(a, b) {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/** 查找 \r\n\r\n 位置（响应头结束），未找到返回 -1 */
function findHeaderEnd(buf) {
	for (let i = 0; i + 3 < buf.length; i++) {
		if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) return i;
	}
	return -1;
}

function readStatusLine(buf) {
	for (let i = 0; i + 1 < buf.length; i++) {
		if (buf[i] === 13 && buf[i + 1] === 10) {
			return new TextDecoder().decode(buf.slice(0, i));
		}
	}
	return '';
}

/**
 * 建立 httpupgrade 传输连接
 * @param {Object} config {address, port, path, tls, sni}
 * @param {Function} log
 * @returns {Promise<{readable:ReadableStream,writable:WritableStream,closed:Promise<void>,send:(d:Uint8Array)=>Promise<void>}|null>}
 */
export async function httpUpgradeConnect(config, log) {
	const host = config.sni && config.sni !== '' ? config.sni : config.address;
	const port = Number(config.port);
	let socket;
	try {
		socket = globalThis.connect ? globalThis.connect({
			hostname: host,
			port,
			secureTransport: config.tls ? 'on' : 'off'
		}) : undefined;
	} catch (e) {
		log(`[VLESS/httpupgrade] connect error: ${e.message}`);
		return null;
	}
	if (!socket) {
		log('[VLESS/httpupgrade] connect unavailable');
		return null;
	}

	const path = config.path && config.path.startsWith('/') ? config.path : `/${config.path || ''}`;
	const requestHead = `GET ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`;

	const reader = socket.readable.getReader();
	let closedResolve;
	const closedPromise = new Promise((resolve) => { closedResolve = resolve; });
	(socket.closed || Promise.resolve()).then(closedResolve, closedResolve);

	let buffer = new Uint8Array(0);
	let remainder = new Uint8Array(0);

	try {
		await Promise.race([
			(async () => {
				const writer = socket.writable.getWriter();
				try {
					await writer.write(new TextEncoder().encode(requestHead));
				} finally {
					try { writer.releaseLock(); } catch (e) { /* ignore */ }
				}
				// 读取响应头直到 \r\n\r\n
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value && value.byteLength > 0) {
						buffer = concatBytes(buffer, value);
						const end = findHeaderEnd(buffer);
						if (end >= 0) {
							remainder = buffer.slice(end + 4);
							return;
						}
					}
				}
				throw new Error('connection closed during handshake');
			})(),
			new Promise((_, reject) => setTimeout(() => reject(new Error('Handshake timeout')), HANDSHAKE_TIMEOUT))
		]);
	} catch (e) {
		log(`[VLESS/httpupgrade] handshake failed: ${e.message}`);
		try { socket.close(); } catch (err) { /* ignore */ }
		return null;
	}

	const statusLine = readStatusLine(buffer);
	if (!/^HTTP\/1\.1 101/.test(statusLine)) {
		log(`[VLESS/httpupgrade] upgrade rejected: ${statusLine}`);
		try { socket.close(); } catch (err) { /* ignore */ }
		return null;
	}

	const readable = new ReadableStream({
		start(controller) {
			if (remainder.byteLength > 0) controller.enqueue(remainder);
			(async () => {
				try {
					for (;;) {
						const { done, value } = await reader.read();
						if (done) break;
						if (value && value.byteLength > 0) controller.enqueue(value);
					}
					try { controller.close(); } catch (e) { /* ignore */ }
				} catch (e) {
					try { controller.error(e); } catch (err) { /* ignore */ }
				}
			})();
		},
		cancel() { try { reader.cancel(); } catch (e) { /* ignore */ } }
	});

	return {
		readable,
		writable: socket.writable,
		closed: closedPromise,
		send: async (data) => {
			const writer = socket.writable.getWriter();
			try {
				await writer.write(data);
			} finally {
				try { writer.releaseLock(); } catch (e) { /* ignore */ }
			}
		}
	};
}
