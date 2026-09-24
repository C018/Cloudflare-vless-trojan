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
import { handleTcpOutbound, resolveOutbound } from '../outbound/tcp.js';
import { vlessOutboundConnect } from '../outbound/vless.js';
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
	const writer = remoteSocket.writable.getWriter();

	// io -> remote（客户端上行）
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
			log(`upstream read error: ${e.message}`);
		}
	})();

	// remote -> io（远端下行）
	try {
		const reader = remoteSocket.readable.getReader();
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value && value.byteLength > 0) {
				downBytes += value.byteLength;
				await io.write(value);
			}
		}
	} catch (e) {
		log(`tcp remote read error: ${e.message}`);
	}

	closed = true;
	try { writer.releaseLock(); } catch (e) { /* ignore */ }
	try { await remoteSocket.writable.close(); } catch (e) { /* ignore */ }
	try { await io.close(); } catch (e) { /* ignore */ }
	// 等待上行循环退出（避免竞态后 io 已关闭仍 write）
	await upstream.catch(() => {});

	await recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
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

	await recordTraffic(config, userRecord, kind, upBytes, downBytes, log);
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
