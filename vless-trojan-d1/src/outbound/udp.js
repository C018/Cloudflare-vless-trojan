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
		// 空帧：remaining 用 subarray 视图零拷贝（原 slice 每空帧复制一次剩余数据）
		return { frame: new Uint8Array(0), remaining: accumulator.subarray(2), needMore: false };
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
	// 动态扩容累积缓冲 + 游标拆帧：原实现每块 new 全量数组 + 两次 set，N 块累积总拷贝 O(N²)；
	// 改为单缓冲原地追加，拆帧后仅 copyWithin 搬移剩余数据，总拷贝摊还 O(N)（扩容 2 倍封顶）。
	let buf = new Uint8Array(0);
	let start = 0; // 有效数据起点（已拆帧消耗的前缀）
	let end = 0;   // 有效数据终点
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value || value.byteLength === 0) continue;
			// 追加前先确保尾部有足够空间（必要时搬移剩余数据 + 扩容）
			if (end + value.byteLength > buf.length) {
				const need = end - start + value.byteLength;
				const nb = new Uint8Array(Math.max(buf.length * 2 || 4096, need));
				nb.set(buf.subarray(start, end), 0);
				buf = nb;
				end -= start;
				start = 0;
			} else if (start > 0) {
				// 无扩容但存在已消耗前缀：原地搬移剩余数据到开头，保持连续可拆
				buf.copyWithin(0, start, end);
				end -= start;
				start = 0;
			}
			buf.set(value, end);
			end += value.byteLength;
			// 拆出所有完整帧（空帧跳过不回调，语义与 extractFrame 一致）
			for (;;) {
				if (end - start < 2) break;
				const len = (buf[start] << 8) | buf[start + 1];
				if (len === 0) { start += 2; continue; }
				if (end - start < 2 + len) break;
				const frame = buf.slice(start + 2, start + 2 + len);
				start += 2 + len;
				try { await onFrame(frame); } catch (e) { log(`udp frame handler error: ${e.message}`); }
			}
		}
	} catch (e) {
		log(`readUdpFrames error: ${e.message}`);
	} finally {
		try { reader.releaseLock(); } catch (e) { /* ignore */ }
	}
}
