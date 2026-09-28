/**
 * 非 WebSocket 入站：grpc / xhttp
 * grpc：请求 body 按 gRPC 消息帧（1 字节压缩标志 + 4 字节长度 + payload）封装
 *      （对应 xray grpc transport，POST /{serviceName}/Tun）
 * xhttp：请求 body 直接承载 VLESS/Trojan 字节流（对应 xray 26.x stream-one，POST {path}/）
 * 均通过 proxy-session.js 处理代理逻辑，响应以流式 body 写回。
 */

import { processProxySession } from './proxy-session.js';

/**
 * 动态扩容追加：单缓冲原地写入，按需 2 倍扩容，避免每读一块全量重建数组的 O(N²) 拷贝。
 * 首包累积 / grpc 帧缓冲在弱网分片多（几十块小片）时拷贝量可降一个数量级。
 * @param {{buf:Uint8Array|null,len:number}} st 累积状态
 * @param {Uint8Array} value 新数据
 */
function appendBytes(st, value) {
	if (!st.buf) {
		st.buf = new Uint8Array(Math.max(value.byteLength, 4096));
		st.buf.set(value, 0);
		st.len = value.byteLength;
		return;
	}
	const need = st.len + value.byteLength;
	if (need > st.buf.length) {
		const nb = new Uint8Array(Math.max(st.buf.length * 2, need));
		nb.set(st.buf.subarray(0, st.len), 0);
		st.buf = nb;
	}
	st.buf.set(value, st.len);
	st.len = need;
}

/**
 * 尝试判定缓冲是否已含完整入站协议头（VLESS 或标准 Trojan），返回头长度；不足/无法判定返回 null。
 * 用于 xhttp 入站首包：按协议头真实结构判定完整性，替代固定 60 字节阈值——
 * 固定阈值对 <60B 的 VLESS 短首包（如空/短 payload 的 TCP、DNS 小查询）会永久挂起
 * （xhttp 请求体在连接生命周期内不 EOF），且 60B 不足以容纳标准 Trojan 头
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

/** grpc 下行帧单缓冲构造：5B 帧头 + protobuf 包裹体（0x0a + varint(len) + data）一次预分配写入。
 *  替代 makeGrpcFrame(encodeGrpcPayload(data)) 的 2 次分配 2 次全量拷贝，grpc 高吞吐时帧封装 CPU 减半 */
function makeGrpcFrameSingle(data) {
	const vlen = data.length;
	let varintLen = 1;
	for (let n = vlen >>> 7; n > 0; n >>>= 7) varintLen++;
	const out = new Uint8Array(5 + 1 + varintLen + vlen);
	// 5B gRPC 帧头：1B 压缩标志(0) + 4B 大端长度（整个 protobuf 包裹体长度）
	out[0] = 0;
	out[1] = ((1 + varintLen + vlen) >>> 24) & 0xff;
	out[2] = ((1 + varintLen + vlen) >>> 16) & 0xff;
	out[3] = ((1 + varintLen + vlen) >>> 8) & 0xff;
	out[4] = (1 + varintLen + vlen) & 0xff;
	// protobuf 包裹：0x0a + varint(len) + data
	out[5] = 0x0a;
	let vi = 6, n = vlen;
	for (;;) {
		let b = n & 0x7f;
		n >>>= 7;
		if (n > 0) b |= 0x80;
		out[vi++] = b;
		if (n === 0) break;
	}
	out.set(data, vi);
	return out;
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

/**
 * XHTTP 入站（xray 26.x stream-one）：POST {wsPath}/，单请求双向流。
 * 上行 = request.body（VLESS/Trojan 首包 + 业务数据），下行 = response body。
 * 裸流桥接（请求体不 EOF，首包累积判定协议头，后续块直通），
 * 仅响应头按 XHTTP stream-one 约定（text/event-stream + X-Accel-Buffering: no，
 * 对齐 xray 服务端 hub.go：CDN 层长连接不缓冲）。
 */
export async function handleXHTTPInbound(request, config, env) {
	const log = (...args) => console.log('[xhttp-in]', ...args);
	if (!request.body) {
		return new Response('Bad Request', { status: 400 });
	}
	const bodyReader = request.body.getReader();
	const { readable, writable } = new TransformStream();
	const writer = writable.getWriter();

	const io = {
		firstReadDone: false,
		read: async () => {
			if (!io.firstReadDone) {
				io.firstReadDone = true;
				const st = { buf: null, len: 0 };
				for (;;) {
					const { done, value } = await bodyReader.read();
					if (done) return st.len > 0 ? st.buf.subarray(0, st.len) : null;
					appendBytes(st, value instanceof Uint8Array ? value : new Uint8Array(value));
					// 协议头完整性判定：tryParseHeaderLength 返回头长度；须等到
					// 实际缓冲 ≥ 头长度才返回（长度已知但字节未收齐时继续累积，
					// 否则域名/地址会被截断交给下游解析，如 "www.g"）
					const hlen = tryParseHeaderLength(st.buf.subarray(0, st.len));
					if (hlen !== null && st.len >= hlen) return st.buf.subarray(0, st.len);
				}
			}
			const { done, value } = await bodyReader.read();
			if (done) return null;
			if (!value || value.byteLength === 0) return new Uint8Array(0);
			return value instanceof Uint8Array ? value : new Uint8Array(value);
		},
		write: (data) => writer.write(data),
		close: async () => {
			try { await bodyReader.cancel(); } catch (e) { /* ignore */ }
			try { await writer.close(); } catch (e) { /* ignore */ }
		}
	};

	processProxySession(config, env, log, io).catch((e) => {
		log(`xhttp handler error: ${e.message || e}`);
		bodyReader.cancel().catch(() => {});
		writer.close().catch(() => {});
	});

	return new Response(readable, {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-store',
			'X-Accel-Buffering': 'no'
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

	let pending = { buf: null, len: 0 };

	const io = {
		read: async () => {
			// 持续补充缓冲直到凑齐一个完整 gRPC 帧
			for (;;) {
				if (pending.len >= 5) {
					const len = (pending.buf[1] << 24) | (pending.buf[2] << 16) | (pending.buf[3] << 8) | pending.buf[4];
					if (pending.len >= 5 + len) {
						const payload = pending.buf.slice(5, 5 + len);
						// 剩余字节原地前移，避免每次拆帧全量重建缓冲
						pending.buf.copyWithin(0, 5 + len, pending.len);
						pending.len -= 5 + len;
						return decodeGrpcPayload(payload);
					}
				}
				const { done, value } = await bodyReader.read();
				if (done) {
					if (pending.len === 0) return null;
					// 尾部不足一帧：不足 5 字节的 gRPC 帧头残留直接丢弃
					// （无法构成有效载荷，混入会把帧头字节当业务数据转发）；
					// 其余按剩余原始字节容忍处理
					if (pending.len < 5) {
						pending.len = 0;
						return new Uint8Array(0);
					}
					const rest = pending.buf.slice(0, pending.len);
					pending.len = 0;
					return decodeGrpcPayload(rest);
				}
				appendBytes(pending, value instanceof Uint8Array ? value : new Uint8Array(value));
			}
		},
		write: (data) => writer.write(makeGrpcFrameSingle(data instanceof Uint8Array ? data : new Uint8Array(data))),
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
