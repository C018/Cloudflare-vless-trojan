/**
 * UDP framing utilities (16-bit big-endian length prefix, matching VLESS UDP over TCP)
 */

/**
 * 读取下一帧 [2B len][payload]，从字节流累积器解析
 * @param {Uint8Array} accumulator
 * @returns {{frame:Uint8Array|null,remaining:Uint8Array,needMore:boolean}}
 */
export function extractFrame(accumulator) {
	if (accumulator.length < 2) {
		return { frame: null, remaining: accumulator, needMore: true };
	}
	const len = (accumulator[0] << 8) | accumulator[1];
	if (len === 0) {
		return { frame: new Uint8Array(0), remaining: accumulator.slice(2), needMore: false };
	}
	if (accumulator.length < 2 + len) {
		return { frame: null, remaining: accumulator, needMore: true };
	}
	return {
		frame: accumulator.slice(2, 2 + len),
		remaining: accumulator.slice(2 + len),
		needMore: false
	};
}

/**
 * 将 payload 包装为 [2B len][payload] 帧
 * @param {Uint8Array} payload
 */
export function wrapUdpFrame(payload) {
	const frame = new Uint8Array(2 + payload.length);
	frame[0] = payload.length >> 8;
	frame[1] = payload.length & 0xff;
	frame.set(payload, 2);
	return frame;
}

/**
 * 将数据块按帧拆分（可能跨 chunk），调用 handler(payload)
 * @param {ReadableStream} sourceStream
 * @param {(payload:Uint8Array)=>void|Promise<void>} onFrame
 * @param {Function} log
 */
export async function readUdpFrames(sourceStream, onFrame, log) {
	const reader = sourceStream.getReader();
	let buffer = new Uint8Array(0);
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value || value.byteLength === 0) continue;
			const merged = new Uint8Array(buffer.length + value.byteLength);
			merged.set(buffer, 0);
			merged.set(value, buffer.length);
			buffer = merged;
			// 拆出所有完整帧
			for (;;) {
				const { frame, remaining, needMore } = extractFrame(buffer);
				if (needMore) { buffer = remaining; break; }
				buffer = remaining;
				if (frame && frame.length > 0) {
					try { await onFrame(frame); } catch (e) { log(`udp frame handler error: ${e.message}`); }
				}
				if (buffer.length < 2) break;
			}
		}
	} catch (e) {
		log(`readUdpFrames error: ${e.message}`);
	} finally {
		try { reader.releaseLock(); } catch (e) { /* ignore */ }
	}
}
