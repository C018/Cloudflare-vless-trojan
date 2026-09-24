/**
 * VLESS outbound transport: h2
 * 最小 HTTP/2 客户端：TCP（可选 TLS）建连后发送 preface + SETTINGS + HEADERS（POST {path}），
 * 后续 DATA 帧直接承载 VLESS 字节流（无 gRPC 封装，对应 xray h2 transport）。
 * 读侧：DATA 帧 payload 直接输出；写侧：VLESS 数据直接放入 DATA 帧。
 */

const H2_PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

const FRAME_DATA = 0x0;
const FRAME_HEADERS = 0x1;
const FRAME_RST_STREAM = 0x3;
const FRAME_SETTINGS = 0x4;
const FRAME_PING = 0x6;
const FRAME_GOAWAY = 0x7;
const FRAME_WINDOW_UPDATE = 0x8;

const FLAG_ACK = 0x1;
const FLAG_END_HEADERS = 0x4;

const MAX_FRAME_SIZE = 16384;
const STREAM_ID = 1;

const encoder = new TextEncoder();

function hpackLiteral(name, value) {
	const nb = encoder.encode(name);
	const vb = encoder.encode(value);
	const out = new Uint8Array(2 + nb.length + 1 + vb.length);
	out[0] = 0x00; // 字面量不索引（无 Huffman）
	out[1] = nb.length;
	out.set(nb, 2);
	out[2 + nb.length] = vb.length;
	out.set(vb, 3 + nb.length);
	return out;
}

function hpackBlock(entries) {
	let out = new Uint8Array(0);
	for (const [n, v] of entries) {
		out = concatBytes(out, hpackLiteral(n, v));
	}
	return out;
}

function h2Frame(type, flags, streamId, payload) {
	const len = payload.length;
	const out = new Uint8Array(9 + len);
	out[0] = (len >> 16) & 0xff;
	out[1] = (len >> 8) & 0xff;
	out[2] = len & 0xff;
	out[3] = type;
	out[4] = flags;
	out[5] = (streamId >> 24) & 0x7f;
	out[6] = (streamId >> 16) & 0xff;
	out[7] = (streamId >> 8) & 0xff;
	out[8] = streamId & 0xff;
	out.set(payload, 9);
	return out;
}

function uint32BE(value) {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, value >>> 0, false);
	return out;
}

function concatBytes(a, b) {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/** 从 reader 精确读取 n 字节；EOF 提前返回 null */
async function readExactly(reader, n) {
	const chunks = [];
	let got = 0;
	while (got < n) {
		const { done, value } = await reader.read();
		if (done) return null;
		if (!value || value.byteLength === 0) continue;
		chunks.push(value);
		got += value.byteLength;
	}
	let out;
	if (chunks.length === 1) {
		out = chunks[0];
	} else {
		out = concatBytes(chunks[0], chunks[1]);
		for (let i = 2; i < chunks.length; i++) out = concatBytes(out, chunks[i]);
	}
	if (out.byteLength > n) {
		return { data: out.slice(0, n), extra: out.slice(n) };
	}
	return { data: out, extra: null };
}

/**
 * 建立 h2 传输连接
 * @param {Object} config {address, port, path, tls, sni}
 * @param {Function} log
 * @returns {Promise<{readable:ReadableStream,writable:WritableStream,closed:Promise<void>,send:(d:Uint8Array)=>Promise<void>}|null>}
 */
export async function h2Connect(config, log) {
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
		log(`[VLESS/h2] connect error: ${e.message}`);
		return null;
	}
	if (!socket) {
		log('[VLESS/h2] connect unavailable');
		return null;
	}

	const writer = socket.writable.getWriter();
	async function writeAll(data) {
		await writer.write(data);
	}

	let closedResolve;
	const closedPromise = new Promise((resolve) => { closedResolve = resolve; });
	(socket.closed || Promise.resolve()).then(closedResolve, closedResolve);

	// ---- 握手：preface + SETTINGS + HEADERS ----
	try {
		await writeAll(encoder.encode(H2_PREFACE));
		await writeAll(h2Frame(FRAME_SETTINGS, 0, 0, new Uint8Array(0)));
		const scheme = config.tls ? 'https' : 'http';
		const path = config.path && config.path.startsWith('/') ? config.path : `/${config.path || ''}`;
		const headerBlock = hpackBlock([
			[':method', 'POST'],
			[':scheme', scheme],
			[':path', path],
			[':authority', `${host}:${port}`],
			['content-length', '0'],
			['user-agent', 'vless-h2/1.0.0']
		]);
		await writeAll(h2Frame(FRAME_HEADERS, FLAG_END_HEADERS, STREAM_ID, headerBlock));
	} catch (e) {
		log(`[VLESS/h2] handshake failed: ${e.message}`);
		try { socket.close(); } catch (err) { /* ignore */ }
		return null;
	}

	const reader = socket.readable.getReader();

	const readable = new ReadableStream({
		start(controller) {
			(async () => {
				let extra = null;
				try {
					for (;;) {
						let payload;
						if (extra) {
							payload = extra;
							extra = null;
						} else {
							const hdr = await readExactly(reader, 9);
							if (!hdr) break;
							const len = (hdr.data[0] << 16) | (hdr.data[1] << 8) | hdr.data[2];
							const type = hdr.data[3];
							const flags = hdr.data[4];
							const streamId = ((hdr.data[5] & 0x7f) << 24) | (hdr.data[6] << 16) | (hdr.data[7] << 8) | hdr.data[8];
							if (len === 0) {
								payload = new Uint8Array(0);
							} else {
								const body = await readExactly(reader, len);
								if (!body) break;
								payload = body.data;
								extra = body.extra;
							}

							if (type === FRAME_DATA && streamId === STREAM_ID) {
								if (payload.byteLength > 0) {
									try { controller.enqueue(payload); } catch (e) { /* ignore */ }
								}
								// 补充窗口，避免大流量阻塞
								await writeAll(h2Frame(FRAME_WINDOW_UPDATE, 0, STREAM_ID, uint32BE(payload.byteLength)));
								await writeAll(h2Frame(FRAME_WINDOW_UPDATE, 0, 0, uint32BE(payload.byteLength)));
								continue;
							}
							if (type === FRAME_SETTINGS) {
								if (!(flags & FLAG_ACK)) {
									await writeAll(h2Frame(FRAME_SETTINGS, FLAG_ACK, 0, new Uint8Array(0)));
								}
								continue;
							}
							if (type === FRAME_PING) {
								if (!(flags & FLAG_ACK)) {
									await writeAll(h2Frame(FRAME_PING, FLAG_ACK, streamId, payload));
								}
								continue;
							}
							if (type === FRAME_GOAWAY || type === FRAME_RST_STREAM) {
								break;
							}
						}
					}
					try { controller.close(); } catch (e) { /* ignore */ }
				} catch (e) {
					log(`[VLESS/h2] read loop error: ${e.message}`);
					try { controller.error(e); } catch (err) { /* ignore */ }
				} finally {
					try { closedResolve(); } catch (e) { /* ignore */ }
				}
			})();
		},
		cancel() { try { reader.cancel(); } catch (e) { /* ignore */ } }
	});

	// 出站写：每个 chunk 直接放入 DATA 帧（>MAX_FRAME 时分帧）
	function dataFramesForPayload(msg) {
		const frames = [];
		let offset = 0;
		while (offset < msg.byteLength) {
			const size = Math.min(MAX_FRAME_SIZE, msg.byteLength - offset);
			frames.push(h2Frame(FRAME_DATA, 0, STREAM_ID, msg.slice(offset, offset + size)));
			offset += size;
		}
		return frames;
	}

	const writable = new WritableStream({
		write(chunk) {
			const payload = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
			return (async () => {
				for (const f of dataFramesForPayload(payload)) await writeAll(f);
			})();
		},
		close() { try { socket.close(); } catch (e) { /* ignore */ } },
		abort() { try { socket.close(); } catch (e) { /* ignore */ } }
	});

	return {
		readable,
		writable,
		closed: closedPromise,
		send: async (data) => {
			for (const f of dataFramesForPayload(data)) await writeAll(f);
		}
	};
}
