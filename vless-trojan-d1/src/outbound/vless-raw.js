/**
 * VLESS outbound transport: raw
 * 直接 TCP 连接远端 VLESS 服务器（tls 时通过 connect secureTransport 建立 TLS），
 * 建连后直接发送 VLESS 头与数据，无任何额外封装。
 */
/**
 * 建立 raw 传输连接
 * @param {Object} config {address, port, tls, sni}
 * @param {Function} log
 * @returns {Promise<{readable:ReadableStream,writable:WritableStream,closed:Promise<void>,send:(d:Uint8Array)=>Promise<void>}|null>}
 */
export async function rawConnect(config, log) {
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
		log(`[VLESS/raw] connect error: ${e.message}`);
		return null;
	}
	if (!socket) {
		log('[VLESS/raw] connect unavailable');
		return null;
	}

	const reader = socket.readable.getReader();
	let closedResolve;
	const closedPromise = new Promise((resolve) => { closedResolve = resolve; });
	(socket.closed || Promise.resolve()).then(closedResolve, closedResolve);

	const readable = new ReadableStream({
		start(controller) {
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
