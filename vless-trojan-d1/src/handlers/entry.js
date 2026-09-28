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

/**
 * 尝试判定缓冲是否已含完整入站协议头（VLESS 或标准 Trojan），返回头长度；不足/无法判定返回 null。
 * 用于 h2 入站首包：按协议头真实结构判定完整性，替代固定 60 字节阈值——
 * 固定阈值对 <60B 的 VLESS 短首包（如空/短 payload 的 TCP、DNS 小查询）会永久挂起
 * （h2 请求体在连接生命周期内不 EOF），且 60B 不足以容纳标准 Trojan 头
 * （IPv4 最小 70B），截断后必然解析失败。
 */
function tryParseHeaderLength(buf) {
	const len = buf.byteLength;
	// 防御：超过 512B 仍未识别出头结构视为异常数据，立即返回避免永久累积
	if (len >= 512) return len;
	if (len >= 1 && buf[0] === 0x00) {
		// VLESS: version(1) + uuid(16) + optLen(1) + opt(optLen) + cmd(1) + port(2) + atyp(1) + addr
		if (len < 18) return null;
		const optLen = buf[17];
		const cmdIndex = 18 + optLen;
		if (len < cmdIndex + 4) return null;
		const atyp = buf[cmdIndex + 3];
		let addrLen;
		if (atyp === 1) addrLen = 4;
		else if (atyp === 2) {
			if (len < cmdIndex + 5) return null;
			addrLen = buf[cmdIndex + 4] + 1;
		} else if (atyp === 3) addrLen = 16;
		else return cmdIndex + 4; // 非法 atyp：交下游 processVlessHeader 报错
		return cmdIndex + 4 + addrLen;
	}
	// Trojan: hex(56) + CRLF + cmd(1) + [CRLF(2)] + atyp(1) + addr + port(2) + CRLF
	// （兼容两种布局：trojan-gfw 官方 CMD 后 CRLF 与 xray/v2ray 实测 CMD 后无 CRLF）
	if (len >= 60 && buf[56] === 0x0d && buf[57] === 0x0a) {
		if (len < 60) return null;
		const cmd = buf[58];
		if (cmd !== 0x01 && cmd !== 0x03) return 60; // 非法 cmd：交下游报错
		const cmdCrlf = buf[59] === 0x0d && buf[60] === 0x0a;
		const atypIndex = cmdCrlf ? 61 : 59;
		if (len < atypIndex + 1) return null;
		const atyp = buf[atypIndex];
		let addrLen;
		if (atyp === 1) addrLen = 4;
		else if (atyp === 3) {
			if (len < atypIndex + 2) return null;
			addrLen = buf[atypIndex + 1] + 1;
		} else if (atyp === 4) addrLen = 16;
		else return atypIndex + 1; // 非法 atyp：交下游报错
		return atypIndex + 1 + addrLen + 2 + 2; // addr + port + final CRLF
	}
	// 非 VLESS（首字节非 0）且未满 60B：可能是未收齐的 Trojan 头，继续累积
	if (len < 60) return null;
	// 满 60B 但既非 VLESS 也非 Trojan 特征：非法数据，交下游报错
	return len;
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
 * xray/v2ray gRPC transport 的真实消息格式（实测 xray 26.7.28 抓包确认）：
 * gRPC 帧 payload = protobuf 消息（field 1 = length-delimited 原始字节流）：
 *   0x0a + varint(len) + data
 * 早期实现把 protobuf 包裹字节（0a XX ...）直接交给 VLESS/Trojan 解析，
 * 首字节 0x0a 被当成 VLESS version（应为 0）拒绝，grpc 入站握手必然失败。
 * 这里在拆帧后剥掉 protobuf 层；若 payload 不是 protobuf（首字节非 0x0a），
 * 按裸数据容忍处理（兼容旧客户端/非标准实现）。
 */
function decodeGrpcPayload(payload) {
	if (payload.length < 2 || payload[0] !== 0x0a) return payload;
	// varint 解码长度；break 时 i 指向最后一个 varint 字节，data 从 i+1 开始
	let len = 0, shift = 0, i = 1;
	for (; i < payload.length && shift < 35; i++) {
		const b = payload[i];
		len |= (b & 0x7f) << shift;
		if ((b & 0x80) === 0) break;
		shift += 7;
	}
	if (i >= payload.length || (payload[i] & 0x80) !== 0) return payload; // varint 未终结（break 时 i 指向最后一个 varint 字节）：按裸数据
	const dataStart = i + 1;
	if (payload.length - dataStart < len) return payload; // 声明长度超剩余：按裸数据容错
	return payload.slice(dataStart, dataStart + len);
}

/** protobuf 包裹：0x0a + varint(len) + data */
function encodeGrpcPayload(data) {
	let n = data.length;
	const varint = [];
	for (;;) {
		let b = n & 0x7f;
		n >>>= 7;
		if (n > 0) b |= 0x80;
		varint.push(b);
		if (n === 0) break;
	}
	const out = new Uint8Array(1 + varint.length + data.length);
	out[0] = 0x0a;
	out.set(varint, 1);
	out.set(data, 1 + varint.length);
	return out;
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
		// 首包累积标志：仅首次读取（协议头）需要累积到 60 字节判定 trojan；
		// 后续每次读取必须直接返回 body 块，否则 <60B 的上行数据（DNS 查询、
		// HTTP 小请求、交互式流量）会被挂起等待凑满——h2 请求体在连接生命周期
		// 内不 EOF，这些数据将永远无法转发到目标，导致 h2 入站不可用。
		firstReadDone: false,
		read: async () => {
			if (!io.firstReadDone) {
				io.firstReadDone = true;
				// 首次读取累积缓冲：CF 可能把单个 DATA 帧拆成多个 body chunk，
				// 若协议头被拆断，proxy-session 会误判 invalid data。按协议头结构
				// 判定完整性（tryParseHeaderLength）：VLESS 短首包 / Trojan 头收齐
				// 即返回，不再硬卡 60 字节（固定阈值会挂起短首包并截断 Trojan 头）。
				let buf = new Uint8Array(0);
				for (;;) {
					const { done, value } = await bodyReader.read();
					if (done) return buf.byteLength > 0 ? buf : null;
					buf = concatBytes(buf, value instanceof Uint8Array ? value : new Uint8Array(value));
					if (tryParseHeaderLength(buf) !== null) return buf;
				}
			}
			// 后续读取：直通返回单个 body 块（不做累积），保持小包低延迟转发
			const { done, value } = await bodyReader.read();
			if (done) return null;
			if (!value || value.byteLength === 0) return new Uint8Array(0);
			return value instanceof Uint8Array ? value : new Uint8Array(value);
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
						return decodeGrpcPayload(payload);
					}
				}
				const { done, value } = await bodyReader.read();
				if (done) {
					if (pending.byteLength === 0) return null;
					// 尾部不足一帧：不足 5 字节的 gRPC 帧头残留直接丢弃
					// （无法构成有效载荷，混入会把帧头字节当业务数据转发）；
					// 其余按剩余原始字节容忍处理
					if (pending.byteLength < 5) {
						pending = new Uint8Array(0);
						return new Uint8Array(0);
					}
					const rest = pending;
					pending = new Uint8Array(0);
					return decodeGrpcPayload(rest);
				}
				pending = concatBytes(pending, value instanceof Uint8Array ? value : new Uint8Array(value));
			}
		},
		write: (data) => writer.write(makeGrpcFrame(encodeGrpcPayload(data instanceof Uint8Array ? data : new Uint8Array(data)))),
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
