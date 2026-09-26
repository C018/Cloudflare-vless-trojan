/**
 * 小包合并器（Coalescing Writer）
 * 解决 Workers 平台高频小帧发送导致的吞吐瓶颈：
 * 出站代理（socks5/http/vless）回包常为 1~4KB 小 chunk，若每个 chunk 都触发一次
 * ws.send / h2 DATA 帧 / gRPC 帧，平台帧开销会显著拉低吞吐（direct 直连 CDN 站点时
 * TCP 段较大故不明显）。
 *
 * 策略：
 * - 单 chunk 达到 highWaterMark → 直通，不引入延迟；
 * - 小 chunk 累积，达到 highWaterMark → 立即 flush；
 * - 不足阈值时启动 flushDelayMs 兜底定时器，避免交互型小流量延迟无限大；
 * - 写入经 promise chain 串行化，保证字节顺序与背压传播。
 */

export const COALESCE_HIGH_WATER_MARK = 32 * 1024; // 32KB：大流量场景减少一半帧数，交互型连接已被上层检测禁用合并器，无延迟代价
export const COALESCE_FLUSH_DELAY_MS = 20;

/**
 * @param {(data:Uint8Array)=>Promise<unknown>} writeFn 实际写入函数（io.write / writer.write）
 * @param {Object} [opts]
 * @param {number} [opts.highWaterMark]
 * @param {number} [opts.flushDelayMs]
 * @param {Function} [opts.log]
 */
export function createCoalescer(writeFn, opts = {}) {
	const highWaterMark = opts.highWaterMark || COALESCE_HIGH_WATER_MARK;
	const flushDelayMs = opts.flushDelayMs != null ? opts.flushDelayMs : COALESCE_FLUSH_DELAY_MS;
	const log = opts.log || (() => {});

	let pending = null;   // Uint8Array
	let pendingLen = 0;
	let timer = null;
	let chain = Promise.resolve();

	const enqueueWrite = (data) => {
		chain = chain.then(() => writeFn(data)).catch((e) => {
			log(`coalesce write error: ${e && e.message ? e.message : e}`);
		});
	};

	const flush = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
		if (pendingLen === 0) return;
		const data = pending;
		pending = null;
		pendingLen = 0;
		enqueueWrite(data);
	};

	const armTimer = () => {
		if (!timer) timer = setTimeout(flush, flushDelayMs);
	};

	return {
		/** 追加一个 chunk；达到阈值立即 flush，未达阈值积攒并挂兜底定时器 */
		push(chunk) {
			if (!chunk || chunk.byteLength === 0) return;
			if (pendingLen === 0 && chunk.byteLength >= highWaterMark) {
				// 大包直通：零拷贝、零延迟
				enqueueWrite(chunk);
				return;
			}
			const merged = new Uint8Array(pendingLen + chunk.byteLength);
			if (pendingLen > 0) merged.set(pending, 0);
			merged.set(chunk, pendingLen);
			pending = merged;
			pendingLen = merged.length;
			if (pendingLen >= highWaterMark) {
				flush();
			} else {
				armTimer();
			}
		},
		/** 立即冲刷积攒数据并等待在途写入完成 */
		flush() {
			flush();
			return chain;
		},
		/** 丢弃积攒数据并取消定时器（连接换路/关闭时使用） */
		destroy() {
			if (timer) {
				clearTimeout(timer);
				timer = null;
			}
			pending = null;
			pendingLen = 0;
		}
	};
}
