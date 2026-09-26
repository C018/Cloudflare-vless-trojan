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
import { createCoalescer } from '../outbound/coalesce.js';
import { decideRoute } from '../routing/engine.js';

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
		try { await io.write(new Uint8Array([0x00, 0x00])); } catch (e) { /* ignore */ }
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
	const firstPayload = new Uint8Array(protocolBuffer.slice(headerResult.rawDataIndex));

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
			io.write(new Uint8Array([0x00, 0x00])).catch(() => { /* ignore */ });
		}
	}, 5000);
	// 直连首包等待超时（对齐 Vless_workers_pages：直连无数据 → retry proxyip）
	const DIRECT_FIRST_PACKET_TIMEOUT = 5000;
	// 当前 direct 路由元信息：是否已走 proxyip
	let routeMeta = directRouteMeta.get(remoteSocket) || null;
	let fallbackDone = false;
	// 上行首包直通标记（换路时重置，保证新链路首包也直通）
	let upGotFirst = false;
	let writer = remoteSocket.writable.getWriter();
	// 上行合并器：客户端 → 出站代理，小包合并降低出站 ws.send / TCP 写频率
	let upCoalescer = createCoalescer((d) => writer.write(d), { log });
	// 下行合并器：出站代理 → 客户端（try 块内惰性创建，收尾在块外 flush，故声明提到函数体顶层）
	let downCoalescer = null;
	// 交互模式检测：观察窗口内累计流量低于阈值 → 判定为请求-响应型连接（测速/网页/API），
	// 立即禁用合并器全程直通，消除小包合并引入的 20ms 级延迟；大流量连接（下载/上传/流媒体）保持合并以保吞吐
	const INTERACTIVE_WINDOW_MS = 1200;
	const INTERACTIVE_BYTES = 128 * 1024;
	let interactive = false;
	let totalBytes = 0;
	const connStart = Date.now();
	const maybeDisableCoalescer = () => {
		if (interactive) return;
		if (Date.now() - connStart >= INTERACTIVE_WINDOW_MS && totalBytes < INTERACTIVE_BYTES) {
			interactive = true;
			log(`interactive flow detected (${totalBytes}B in ${INTERACTIVE_WINDOW_MS}ms), coalescer disabled`);
			upCoalescer.flush();
			if (downCoalescer) downCoalescer.flush();
			upCoalescer.destroy();
			if (downCoalescer) downCoalescer.destroy();
		}
	};

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

	// io -> remote（客户端上行）
	const upstream = (async () => {
		try {
			for (;;) {
				const chunk = await io.read();
				if (chunk === null || chunk === undefined) break;
				if (chunk.byteLength === 0) continue;
				upBytes += chunk.byteLength;
				totalBytes += chunk.byteLength;
				lastActivity = Date.now();
				if (!upGotFirst) {
					// 首包直通：与下行对称，避免交互小请求被合并器拖 20ms
					upGotFirst = true;
					await writer.write(chunk);
				} else {
					maybeDisableCoalescer();
					if (interactive) {
						await writer.write(chunk);
					} else {
						upCoalescer.push(chunk);
					}
				}
			}
		} catch (e) {
			log(`upstream read error: ${e.message}`);
		}
		await upCoalescer.flush();
		upCoalescer.destroy();
	})();

	// remote -> io（远端下行）
	try {
		let reader = remoteSocket.readable.getReader();
		let gotFirst = false;
		// 下行合并器：出站代理 → 客户端，小包合并减少客户端侧帧发送次数；
		// 首包直通保 TTFB，首个包之后的小包才进合并器
		while (true) {
			let result;
			if (!gotFirst && !fallbackDone) {
				let timer = null;
				const readPromise = reader.read().then((r) => ({ tag: 'read', ...r }));
				const timerPromise = new Promise((res) => {
					timer = setTimeout(() => res({ tag: 'timeout' }), DIRECT_FIRST_PACKET_TIMEOUT);
				});
				result = await Promise.race([readPromise, timerPromise]);
				clearTimeout(timer);
			} else {
				result = { tag: 'read', ...(await reader.read()) };
			}

			if (result.tag === 'timeout') {
				log(`no first packet in ${DIRECT_FIRST_PACKET_TIMEOUT}ms (${addressRemote}:${portRemote})`);
				const fb = await tryFallback();
				if (!fb) break;
				upCoalescer.destroy();
				try { writer.releaseLock(); } catch (e) { /* ignore */ }
				remoteSocket = fb;
				writer = remoteSocket.writable.getWriter();
				upCoalescer = createCoalescer((d) => writer.write(d), { log });
				upGotFirst = false;
				routeMeta = directRouteMeta.get(remoteSocket) || null;
				reader = remoteSocket.readable.getReader();
				gotFirst = false;
				continue;
			}

			if (result.done) break;
			if (result.value && result.value.byteLength > 0) {
				gotFirst = true;
				downBytes += result.value.byteLength;
				totalBytes += result.value.byteLength;
				lastActivity = Date.now();
				if (!downCoalescer) {
					downCoalescer = createCoalescer((d) => io.write(d), { log });
					await io.write(result.value);
				} else {
					maybeDisableCoalescer();
					if (interactive) {
						await io.write(result.value);
					} else {
						downCoalescer.push(result.value);
					}
				}
			}
		}
	} catch (e) {
		// 首包到达前的 socket error/close（CF 拦截常表现为连接立即被重置）→ 尝试回退换路
		if (!fallbackDone && downBytes === 0) {
			log(`tcp remote read error before first packet: ${e.message || e}`);
			const fb = await tryFallback();
			if (fb) {
				upCoalescer.destroy();
				try { writer.releaseLock(); } catch (x) { /* ignore */ }
				remoteSocket = fb;
				writer = remoteSocket.writable.getWriter();
				upCoalescer = createCoalescer((d) => writer.write(d), { log });
				upGotFirst = false;
				routeMeta = directRouteMeta.get(remoteSocket) || null;
				fallbackDone = true;
				const reader2 = remoteSocket.readable.getReader();
				if (!downCoalescer) downCoalescer = createCoalescer((d) => io.write(d), { log });
				try {
					while (true) {
						const { done, value } = await reader2.read();
						if (done) break;
						if (value && value.byteLength > 0) {
							downBytes += value.byteLength;
							totalBytes += value.byteLength;
							lastActivity = Date.now();
							if (!gotFirst) {
								gotFirst = true;
								await io.write(value);
							} else {
								maybeDisableCoalescer();
								if (interactive) {
									await io.write(value);
								} else {
									downCoalescer.push(value);
								}
							}
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

	// 冲刷下行积攒数据（保证不丢字节）后收尾
	if (downCoalescer) await downCoalescer.flush();
	closed = true;
	clearInterval(heartbeatTimer);
	upCoalescer.destroy();
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
 * 连接关闭后异步累加流量到 D1
 */
async function recordTraffic(config, userRecord, kind, upBytes, downBytes, log) {
	if (!userRecord) return;
	const table = kind === 'vless' ? 'vless_users' : 'trojan_users';
	try {
		await config.env.DB.prepare(
			`UPDATE ${table} SET up = up + ?, down = down + ? WHERE id = ?`
		).bind(upBytes, downBytes, userRecord.id).run();
	} catch (e) {
		log(`record traffic error: ${e.message}`);
	}
}
