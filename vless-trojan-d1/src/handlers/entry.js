/**
 * 非 WebSocket 入站：h2 / grpc
 * h2：请求 body 直接承载 VLESS/Trojan 字节流（对应 xray h2 transport，POST {path}）
 * grpc：请求 body 按 gRPC 消息帧（1 字节压缩标志 + 4 字节长度 + payload）封装
 *      （对应 xray grpc transport，POST /{serviceName}/Tun）
 * 两者均通过 proxy-session.js 处理代理逻辑，响应以流式 body 写回。
 */

import { processProxySession } from './proxy-session.js';

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
		out = new Uint8Array(chunks[0]);
	} else {
		out = concatBytes(chunks[0], chunks[1]);
		for (let i = 2; i < chunks.length; i++) out = concatBytes(out, chunks[i]);
	}
	return out;
}

function grpcFrameHeader(len) {
	const h = new Uint8Array(5);
	h[0] = 0; // 未压缩
	h[1] = (len >>> 24) & 0xff;
	h[2] = (len >>> 16) & 0xff;
	h[3] = (len >>> 8) & 0xff;
	h[4] = len & 0xff;
	return h;
}

function makeGrpcFrame(payload) {
	return concatBytes(grpcFrameHeader(payload.byteLength), payload);
}

/**
 * h2 入站：POST {wsPath}，body 即 VLESS/Trojan 流
 */
export async function handleH2Inbound(request, config, env) {
	const log = (...args) => console.log('[h2-in]', ...args);
	if (!request.body) {
		return new Response('Bad Request', { status: 400 });
	}
	const bodyReader = request.body.getReader();
	const { readable, writable } = new TransformStream();
	const writer = writable.getWriter();

	const io = {
		read: async () => {
			// 首次读取累积缓冲：CF 可能把单个 DATA 帧拆成多个 body chunk，
			// 若 VLESS/Trojan 头被拆断，proxy-session 会误判 invalid data。
			// 累积到协议头判定阈值（trojan 头固定 60 字节）或 EOF 再返回。
			let buf = new Uint8Array(0);
			for (;;) {
				const { done, value } = await bodyReader.read();
				if (done) return buf.byteLength > 0 ? buf : null;
				buf = concatBytes(buf, value instanceof Uint8Array ? value : new Uint8Array(value));
				if (buf.byteLength >= 60) return buf;
			}
		},
		write: (data) => writer.write(data),
		close: async () => {
			// 必须取消请求体读取：否则 handleTCP 尾部的 upstream 循环
			// 会永久挂起在 bodyReader.read() 上（h2 请求不结束），导致响应流无法干净关闭
			try { await bodyReader.cancel(); } catch (e) { /* ignore */ }
			try { await writer.close(); } catch (e) { /* ignore */ }
		}
	};

	processProxySession(config, env, log, io).catch((e) => {
		log(`h2 handler error: ${e.message || e}`);
		bodyReader.cancel().catch(() => {});
		writer.close().catch(() => {});
	});

	return new Response(readable, {
		status: 200,
		headers: {
			'Content-Type': 'application/octet-stream',
			'Cache-Control': 'no-store'
		}
	});
}

/**
 * grpc 入站：POST {wsPath}/Tun，body 为 gRPC 消息帧
 */
export async function handleGrpcInbound(request, config, env) {
	const log = (...args) => console.log('[grpc-in]', ...args);
	if (!request.body) {
		return new Response('Bad Request', { status: 400 });
	}
	const bodyReader = request.body.getReader();
	const { readable, writable } = new TransformStream();
	const writer = writable.getWriter();

	let pending = new Uint8Array(0);

	const io = {
		read: async () => {
			// 持续补充缓冲直到凑齐一个完整 gRPC 帧
			for (;;) {
				if (pending.byteLength >= 5) {
					const len = (pending[1] << 24) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
					if (pending.byteLength >= 5 + len) {
						const payload = pending.slice(5, 5 + len);
						pending = pending.slice(5 + len);
						return payload;
					}
				}
				const { done, value } = await bodyReader.read();
				if (done) {
					if (pending.byteLength === 0) return null;
					// 尾部不足一帧：按剩余原始字节处理（容忍）
					const rest = pending;
					pending = new Uint8Array(0);
					return rest;
				}
				pending = concatBytes(pending, value instanceof Uint8Array ? value : new Uint8Array(value));
			}
		},
		write: (data) => writer.write(makeGrpcFrame(data instanceof Uint8Array ? data : new Uint8Array(data))),
		close: async () => {
			try { await bodyReader.cancel(); } catch (e) { /* ignore */ }
			try { await writer.close(); } catch (e) { /* ignore */ }
		}
	};

	processProxySession(config, env, log, io).catch((e) => {
		log(`grpc handler error: ${e.message || e}`);
		bodyReader.cancel().catch(() => {});
		writer.close().catch(() => {});
	});

	return new Response(readable, {
		status: 200,
		headers: {
			'Content-Type': 'application/grpc',
			'Cache-Control': 'no-store'
		}
	});
}
