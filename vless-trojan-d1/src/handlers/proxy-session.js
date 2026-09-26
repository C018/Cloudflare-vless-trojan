/**
 * 通用代理会话核心：与具体入口传输（ws / h2 / grpc）解耦。
 * 通过 io 接口读写字节流：
 *   read()  → Promise<Uint8Array|null>   null 表示 EOF
 *   write(d) → Promise<void> | void      向客户端写回
 *   close()  → void                       关闭客户端侧
 * 内部完成：VLESS / Trojan 协议头解析 → 路由 → TCP/UDP 转发 → 流量统计。
 */

import { processVlessHeader } from '../protocol/vless.js';
import { processTrojanHeader, isTrojanLike } from '../protocol/trojan.js';
import { handleTcpOutbound, resolveOutbound, directRouteMeta, connectViaProxyIp, markProxyIpDown } from '../outbound/tcp.js';
import { vlessOutboundConnect } from '../outbound/vless.js';
import { decideRoute } from '../routing/engine.js';

// VLESS 空包帧（0x00 0x00）：服务端握手响应头与心跳保活帧内容相同，复用同一常量避免每连接/每心跳分配
const VLESS_EMPTY_FRAME = new Uint8Array([0x00, 0x00]);

/**
 * 处理一次代理会话（io 已就绪）
 * @param {Object} config
 * @param {Object} env
 * @param {Function} log
 * @param {{read:Function,write:Function,close:Function}} io
 */
export async function processProxySession(config, env, log, io) {
	let protocolBuffer;
	try {
		protocolBuffer = await io.read();
	} catch (e) {
		log(`read first packet error: ${e.message}`);
		try { await io.close(); } catch (err) { /* ignore */ }
		return;
	}
	if (!protocolBuffer) {
		try { await io.close(); } catch (e) { /* ignore */ }
		return;
	}

	let headerResult;
	let userRecord = null;
	let kind = 'vless'; // vless | trojan

	// 入站作用域：自定义路径限定凭据集合；全局路径接受全部启用用户
	const scope = config._inboundScope || null;
	const uuidSet = scope && !scope.all ? scope.vless : config.uuidSet;
	const passwordSet = scope && !scope.all ? scope.trojan : config.passwordSet;

	if (isTrojanLike(protocolBuffer)) {
		headerResult = await processTrojanHeader(protocolBuffer, passwordSet);
		if (headerResult.hasError) {
			log(`trojan header error: ${headerResult.message}`);
			try { await io.close(); } catch (e) { /* ignore */ }
			return;
		}
		kind = 'trojan';
		userRecord = config.trojanIndex[headerResult.userPassword] || null;
	} else {
		headerResult = processVlessHeader(protocolBuffer, uuidSet);
		if (headerResult.hasError) {
			log(`vless header error: ${headerResult.message}`);
			try { await io.close(); } catch (e) { /* ignore */ }
			return;
		}
		// VLESS 服务端握手响应头（version=0, addonLen=0）：xray 等客户端依赖此 2 字节
		// 定位后续响应流，缺失会导致客户端把业务数据前 2 字节误当响应头剥离，
		// 表现为节点能握手成功但实际无法上网（数据错位/连接异常）。
		try { await io.write(VLESS_EMPTY_FRAME); } catch (e) { /* ignore */ }
		userRecord = config.vlessIndex[headerResult.userUuid] || null;
	}

	// 到期时间 / 流量限制校验
	if (userRecord) {
		const nowSec = Math.floor(Date.now() / 1000);
		if (userRecord.expire_at > 0 && userRecord.expire_at < nowSec) {
			log(`${kind} user '${userRecord.remark || userRecord.uuid || userRecord.password}' expired`);
			try { await io.close(); } catch (e) { /* ignore */ }
			return;
		}
		if (userRecord.traffic_limit > 0 && (Number(userRecord.up) + Number(userRecord.down)) >= Number(userRecord.traffic_limit)) {
			log(`${kind} user '${userRecord.remark || userRecord.uuid || userRecord.password}' traffic limit reached`);
			try { await io.close(); } catch (e) { /* ignore */ }
			return;
		}
	}

	const { addressType, addressRemote, portRemote, isUDP } = headerResult;
	// 首包零拷贝：subarray 视图直接复用协议头 buffer（原 slice 每连接复制一次 payload）
	const firstPayload = (protocolBuffer instanceof Uint8Array
		? protocolBuffer
		: new Uint8Array(protocolBuffer)
	).subarray(headerResult.rawDataIndex);

	let route;
	try {
		route = await decideRoute(config, addressType, addressRemote);
	} catch (e) {
		log(`route error: ${e.message}`);
		try { await io.close(); } catch (err) { /* ignore */ }
		return;
	}

	if (isUDP) {
		await handleUDP(io, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log);
	} else {
		await handleTCP(io, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log);
	}
}

async function handleTCP(io, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log) {
	const outbound = resolveOutbound(config, route.outbound);
	const rawClientData = firstPayload && firstPayload.length > 0 ? firstPayload : new Uint8Array(0);

	const attempts = [outbound];
	if (outbound !== 'direct' && outbound !== 'reject') attempts.push('direct');

	let remoteSocket = null;
	let lastError = null;
	for (const ob of attempts) {
		try {
			remoteSocket = await handleTcpOutbound({
				config, outbound: ob, addressType, addressRemote, portRemote, rawClientData, log
			});
		} catch (e) {
			lastError = e;
			remoteSocket = null;
		}
		if (remoteSocket) break;
	}

	if (!remoteSocket) {
		log(`tcp connect failed: ${lastError ? lastError.message : 'no outbound available'}`);
		try { await io.close(); } catch (e) { /* ignore */ }
		return;
	}

	let upBytes = 0;
	let downBytes = 0;
	let closed = false;
	// VLESS 空包心跳保活：CF Workers 平台约 30s 无数据活动即断开 WebSocket，
	// 空闲超过阈值时向客户端发空包帧（0x00 0x00），保持连接活跃（xray/sing-box 客户端原生支持空包探测）。
	const HEARTBEAT_INTERVAL = 15000;
	let lastActivity = Date.now();
	const heartbeatTimer = setInterval(() => {
		if (closed) return;
		if (Date.now() - lastActivity >= HEARTBEAT_INTERVAL) {
			lastActivity = Date.now();
			io.write(VLESS_EMPTY_FRAME).catch(() => { /* ignore */ });
		}
	}, 5000);
	// 直连首包等待超时（对齐 Vless_workers_pages：直连无数据 → retry proxyip）
	const DIRECT_FIRST_PACKET_TIMEOUT = 5000;
	// 当前 direct 路由元信息：是否已走 proxyip
	let routeMeta = directRouteMeta.get(remoteSocket) || null;
	let fallbackDone = false;
	let writer = remoteSocket.writable.getWriter();

	/**
	 * 首包前直连无响应 → 回退换路：
	 *  - 已走 proxyip：标记 down，改直连（下一次同类连接直接直连）
	 *  - 未走 proxyip（直连被 CF 静默丢弃/重置）：改走 proxyip 重连（仅 443 TLS 流量适用）
	 * @returns {Promise<Object|null>} 新 socket 或 null
	 */
	const tryFallback = async () => {
		if (fallbackDone) return null;
		fallbackDone = true;
		const proxyipEnabled = (!!config.proxyipHost || !!config.proxyipOutbound) && !config.proxyipDisabled;
		try { await remoteSocket.close(); } catch (e) { /* ignore */ }
		if (routeMeta && routeMeta.usedProxyIp) {
			markProxyIpDown(log);
			log(`proxyip ${addressRemote}:${portRemote} no first packet, degrade to direct retry`);
			try {
				const s = await handleTcpOutbound({
					config, outbound: 'direct', addressType, addressRemote, portRemote, rawClientData, log
				});
				return s || null;
			} catch (e) {
				log(`direct retry error: ${e.message}`);
				return null;
			}
		}
		if (!proxyipEnabled || portRemote !== 443) return null;
		log(`direct ${addressRemote}:${portRemote} no first packet, retry via proxyip`);
		try {
			return await connectViaProxyIp(config, addressRemote, portRemote, rawClientData, log);
		} catch (e) {
			log(`proxyip retry error: ${e.message}`);
			return null;
		}
	};

	// io -> remote（客户端上行，全程直通：最小延迟优先，不做小包合并）
	const upstream = (async () => {
		try {
			for (;;) {
				const chunk = await io.read();
				if (chunk === null || chunk === undefined) break;
				if (chunk.byteLength === 0) continue;
				upBytes += chunk.byteLength;
				lastActivity = Date.now();
				await writer.write(chunk);
			}
		} catch (e) {
			log(`upstream read error: ${e.message}`);
		}
	})();

	// remote -> io（远端下行，全程直通：最小延迟优先，不做小包合并）
	try {
		let reader = remoteSocket.readable.getReader();
		let gotFirst = false;
		while (true) {
			if (!gotFirst && !fallbackDone) {
				// 首包竞态：直连无数据 → 超时换路（仅首个下行包前需要，避免拖长首字节延迟）
				let timer = null;
				const readPromise = reader.read().then((r) => ({ tag: 'read', ...r }));
				const timerPromise = new Promise((res) => {
					timer = setTimeout(() => res({ tag: 'timeout' }), DIRECT_FIRST_PACKET_TIMEOUT);
				});
				const result = await Promise.race([readPromise, timerPromise]);
				clearTimeout(timer);

				if (result.tag === 'timeout') {
					// 不在此打日志：tryFallback 内部已按降级/换路路径记录（避免与 no first packet 重复刷屏）
					const fb = await tryFallback();
					if (!fb) break;
					try { writer.releaseLock(); } catch (e) { /* ignore */ }
					remoteSocket = fb;
					writer = remoteSocket.writable.getWriter();
					routeMeta = directRouteMeta.get(remoteSocket) || null;
					reader = remoteSocket.readable.getReader();
					gotFirst = false;
					continue;
				}

				if (result.done) break;
				if (result.value && result.value.byteLength > 0) {
					gotFirst = true;
					downBytes += result.value.byteLength;
					lastActivity = Date.now();
					await io.write(result.value);
				}
				continue;
			}

			// 首包竞态结束后：普通下行循环（直读解构，避免每帧构造 {tag:'read',...} 对象 + spread 分配）
			const { done, value } = await reader.read();
			if (done) break;
			if (value && value.byteLength > 0) {
				gotFirst = true;
				downBytes += value.byteLength;
				lastActivity = Date.now();
				await io.write(value);
			}
		}
	} catch (e) {
		// 首包到达前的 socket error/close（CF 拦截常表现为连接立即被重置）→ 尝试回退换路
		if (!fallbackDone && downBytes === 0) {
			log(`tcp remote read error before first packet: ${e.message || e}`);
			const fb = await tryFallback();
			if (fb) {
				try { writer.releaseLock(); } catch (x) { /* ignore */ }
				remoteSocket = fb;
				writer = remoteSocket.writable.getWriter();
				routeMeta = directRouteMeta.get(remoteSocket) || null;
				fallbackDone = true;
				const reader2 = remoteSocket.readable.getReader();
				try {
					while (true) {
						const { done, value } = await reader2.read();
						if (done) break;
						if (value && value.byteLength > 0) {
							downBytes += value.byteLength;
							lastActivity = Date.now();
							await io.write(value);
						}
					}
				} catch (e2) {
					log(`fallback remote read error: ${e2.message || e2}`);
				}
			}
		} else {
			log(`tcp remote read error: ${e.message || e}`);
		}
	}

	closed = true;
	clearInterval(heartbeatTimer);
	try { writer.releaseLock(); } catch (e) { /* ignore */ }
	try { await remoteSocket.writable.close(); } catch (e) { /* ignore */ }
	try { await io.close(); } catch (e) { /* ignore */ }
	// 等待上行循环退出（避免竞态后 io 已关闭仍 write）
	await upstream.catch(() => {});

	recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
}

async function handleUDP(io, config, addressType, addressRemote, portRemote, firstPayload, userRecord, kind, route, log) {
	// UDP 出站：系统设置 udp_outbound 指定出站名，从出站代理中匹配该名称的出站（仅 vless 支持 UDP）
	let vlessOb = null;
	const udpName = (config.udpOutbound || '').trim();
	if (udpName) {
		const ob = config.outboundByName[udpName];
		if (ob && ob.type === 'vless') {
			vlessOb = ob;
		} else {
			log(`udp outbound '${udpName}' not found or not vless (only vless supports udp)`);
			try { await io.close(); } catch (e) { /* ignore */ }
			return;
		}
	} else {
		// 未配置 udp 出站代理：优先路由出站（若为 vless），否则取第一个 vless 出站
		if (route.outbound && route.outbound !== 'direct' && route.outbound !== 'reject') {
			const ob = resolveOutbound(config, route.outbound);
			if (ob !== 'direct' && ob !== 'reject' && ob.type === 'vless') vlessOb = ob;
		}
		if (!vlessOb) vlessOb = config.outbounds.find((o) => o.type === 'vless');
	}
	if (!vlessOb) {
		log('udp requires a vless outbound, none configured');
		try { await io.close(); } catch (e) { /* ignore */ }
		return;
	}

	const firstFrame = firstPayload && firstPayload.length > 0 ? firstPayload : new Uint8Array([0, 0]);
	const conn = await vlessOutboundConnect(
		{ address: vlessOb.address, port: Number(vlessOb.port), uuid: vlessOb.uuid, path: vlessOb.path, tls: !!vlessOb.tls, sni: vlessOb.sni || '', transport: vlessOb.transport || 'ws' },
		0x02, addressType, addressRemote, portRemote, firstFrame, log
	);
	if (!conn) {
		log('udp vless outbound connect failed');
		try { await io.close(); } catch (e) { /* ignore */ }
		return;
	}

	let upBytes = 0;
	let downBytes = 0;
	const writer = conn.writable.getWriter();

	const upstream = (async () => {
		try {
			for (;;) {
				const chunk = await io.read();
				if (chunk === null || chunk === undefined) break;
				if (chunk.byteLength === 0) continue;
				upBytes += chunk.byteLength;
				await writer.write(chunk);
			}
		} catch (e) {
			log(`udp upstream read error: ${e.message}`);
		}
	})();

	try {
		const outReader = conn.readable.getReader();
		while (true) {
			const { done, value } = await outReader.read();
			if (done) break;
			if (value && value.byteLength > 0) {
				downBytes += value.byteLength;
				await io.write(value);
			}
		}
	} catch (e) {
		log(`udp read error: ${e.message}`);
	}

	try { writer.releaseLock(); } catch (e) { /* ignore */ }
	try { await conn.writable.close(); } catch (e) { /* ignore */ }
	try { await io.close(); } catch (e) { /* ignore */ }
	await upstream.catch(() => {});

	recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
}

/**
 * 流量统计批量 flush 合并写：
 * 连接关闭不再逐条 UPDATE，而是先聚合到进程级缓冲，按 2s 时间窗口合并，
 * 窗口结束时用 D1 batch() 一次提交所有待写用户（同用户多次连接合并为一条 UPDATE）。
 * 缓冲条数达到 32 时提前 flush，避免高峰长时间不落库。
 * 写入失败时把快照回放回缓冲并重试（不静默丢弃计数）。
 * 注意：与改造前一致为尽力而为写入（无 waitUntil，请求结束 isolate 冻结可能丢失
 * 最后窗口的数据），短连接高频场景 D1 写入量可降一个数量级。
 */
const TRAFFIC_FLUSH_WINDOW = 2000; // 聚合窗口：2s 内的连接关闭合并为一次批量写
const TRAFFIC_FLUSH_MAX_ITEMS = 32; // 缓冲上限：达到后立即 flush
const trafficBuffer = new Map(); // `${table}:${id}` -> { up, down }
let trafficTimer = null;

async function flushTrafficBuffer(DB) {
	if (!trafficBuffer.size) return;
	const items = [...trafficBuffer.entries()];
	trafficBuffer.clear();
	try {
		const stmts = items.map(([key, v]) => {
			const idx = key.lastIndexOf(':');
			const table = key.slice(0, idx);
			const id = Number(key.slice(idx + 1));
			return DB.prepare(`UPDATE ${table} SET up = up + ?, down = down + ? WHERE id = ?`).bind(v.up, v.down, id);
		});
		await DB.batch(stmts);
	} catch (e) {
		// 失败回放缓冲并安排重试，避免计数永久丢失
		for (const [k, v] of items) {
			const cur = trafficBuffer.get(k);
			if (cur) { cur.up += v.up; cur.down += v.down; }
			else trafficBuffer.set(k, v);
		}
		scheduleTrafficFlush(DB);
	}
}

function scheduleTrafficFlush(DB) {
	if (trafficTimer) return;
	trafficTimer = setTimeout(() => {
		trafficTimer = null;
		flushTrafficBuffer(DB);
	}, TRAFFIC_FLUSH_WINDOW);
}

/**
 * 连接关闭后异步聚合流量：入缓冲 + 窗口 flush（合并写）
 */
async function recordTraffic(config, userRecord, kind, upBytes, downBytes, log) {
	if (!userRecord) return;
	const table = kind === 'vless' ? 'vless_users' : 'trojan_users';
	const key = `${table}:${userRecord.id}`;
	const e = trafficBuffer.get(key);
	if (e) { e.up += upBytes; e.down += downBytes; }
	else trafficBuffer.set(key, { up: upBytes, down: downBytes });
	scheduleTrafficFlush(config.env.DB);
	if (trafficBuffer.size >= TRAFFIC_FLUSH_MAX_ITEMS) {
		try { await flushTrafficBuffer(config.env.DB); }
		catch (err) { log(`record traffic error: ${err.message}`); }
	}
}
