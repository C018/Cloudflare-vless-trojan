/**
 * vless-trojan-d1 entry: unified Worker router
 *
 * 路由优先级：
 *  /admin /admin/api/*            → 后台页面 + REST API
 *  /geo-update-cron               → Cron geo 更新
 *  {ws_path} (Upgrade)            → vless / trojan 入站
 *  /subscribe /{cred}/subscribe   → 订阅生成
 *  /{uuid|password}               → 单节点配置页
 *  其他                            → Alist 风伪装页
 */

import { connect } from 'cloudflare:sockets';
import { createRequestConfig, composeInboundScope } from './config/defaults.js';
import { handleWebSocketUpgrade } from './handlers/websocket.js';
import { handleH2Inbound, handleGrpcInbound, handleXHTTPInbound, handleXHTTPAutoDown, handleXHTTPAutoUp } from './handlers/entry.js';
import { handleHttp } from './handlers/http.js';
import { handleAdminApi, runGeoUpdateTask } from './admin/api.js';
import { buildAdminUI } from './admin/ui.js';
import { handleCron, scheduled } from './cron.js';

// Workers 平台 Socket 建连能力注入：direct / proxyip / socks5 / http 出站均依赖 globalThis.connect
globalThis.connect = connect;

/**
 * XHTTP auto 模式路径匹配：xray 26.x 的 xhttp transport 在 auto 模式下
 * 将数据写入 POST /{basePath}/{randomUuid}（或 /{basePath}/{randomUuid}/0），
 * 路径带随机 UUID 段，无法直接命中 inboundPathMap 的精确路径。
 * 匹配规则：以某入站 basePath + '/' 开头，且第一段为 32 位 hex（随机 UUID）。
 * 返回 { basePath, uuid, scopes }；不匹配返回 null。
 */
function matchXhttpAutoPath(config, path) {
	if (path.length <= 2) return null;
	for (const base of config.inboundPathMap.keys()) {
		if (base.length < 2) continue;
		const prefix = base + '/';
		if (path.startsWith(prefix)) {
			const rest = path.slice(prefix.length);
			const seg = rest.split('/')[0];
			// xray 26.x auto 模式随机段实际为带连字符的 UUID v4（36 字符）；老版本/部分实现为 32 位纯 hex，一并兼容
			if (/^[0-9a-fA-F-]{36}$/.test(seg) && seg.split('-').length === 5
				|| /^[0-9a-fA-F]{32}$/.test(seg)) {
				return { basePath: base, uuid: seg, scopes: config.inboundPathMap.get(base) };
			}
		}
	}
	return null;
}

export default {
	/**
	 * @param {import('@cloudflare/workers-types').Request} request
	 * @param {Object} env
	 * @param {Object} ctx
	 */
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const path = url.pathname;

		try {
			// 1) 后台管理
			if (path.startsWith('/admin')) {
				const config = await createRequestConfig(request, env, { ensureAdmin: true });
				if (path.startsWith('/admin/api/')) {
					return await handleAdminApi(request, config, ctx);
				}
				// /admin /admin/ 及 /admin 下其它路径 → 后台 UI（首次部署附带初始密码提示）
				const uiHtml = buildAdminUI(config.adminTempPassword);
				// 已设置管理密码时页面为静态内容，允许 CDN/浏览器缓存 5 分钟；首次部署含临时密码提示时禁止缓存
				const cacheControl = config.adminTempPassword ? 'no-store' : 'public, max-age=300';
				return new Response(uiHtml, {
					headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': cacheControl }
				});
			}

			// 2) Cron geo 更新
			if (path === '/geo-update-cron') {
				return await handleCron(request, env);
			}

			// 3) 代理入站：按入站路径映射 + 请求特征自动分发（同一凭据同时支持 ws / grpc / h2）
			const config = await createRequestConfig(request, env);
			// grpc 客户端（xray 等）以 /{serviceName}/Tun 建流；旧订阅链接的 serviceName
			// 曾带前导斜杠，会请求 //path/Tun 双斜杠路径。压缩连续斜杠后兼容这类存量链接，
			// 正常路径无连续斜杠时 replace 返回原值，不影响现有路由。
			const xhttpAutoMatch = matchXhttpAutoPath(config, path);
			const scopes = config.inboundPathMap.get(path)
				// XHTTP 客户端（xray 26.x）对 path 自动补尾斜杠（POST /{path}/），
				// 归一化尾斜杠后再查映射，兼容 xhttp 与既有 ws/grpc/h2 路径。
				|| config.inboundPathMap.get(path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path)
				|| config.inboundPathMap.get(path.replace(/\/+/g, '/'))
				// XHTTP auto 模式：GET/POST /{basePath}/{randomUuid}[/N]，路径带随机 UUID 段
				|| (xhttpAutoMatch ? xhttpAutoMatch.scopes : null);
			if (scopes && scopes.length > 0) {
				config._inboundScope = composeInboundScope(scopes);
				const upgrade = String(request.headers.get('Upgrade') || '').toLowerCase();
				const contentType = String(request.headers.get('Content-Type') || '').toLowerCase();
				// grpc 判定仅看 /Tun 后缀：XHTTP（stream-one）请求同样携带
				// application/grpc 头，若按 content-type 判定会被误入 grpc 帧拆包，
				// 导致裸协议流被 gRPC 帧头污染、会话错乱。
				const isGrpc = path.endsWith('/Tun');
				// XHTTP auto/stream-up/packet-up 跨请求会话：
				//   GET /{basePath}/{uuid} → 建立下行流会话
				//   POST /{basePath}/{uuid}[/N] → 上行数据（长流或分包）
				// 必须优先于其它判定：GET 无 body 原本会落伪装页、POST 分包
				// 按 stream-one 处理会建立错乱隧道（下行数据写进 POST 响应被丢弃）。
				if (xhttpAutoMatch && request.method === 'GET') {
					return await handleXHTTPAutoDown(request, config, env, xhttpAutoMatch.uuid);
				}
				if (xhttpAutoMatch && request.method === 'POST') {
					return await handleXHTTPAutoUp(request, config, env, xhttpAutoMatch.uuid);
				}
				// XHTTP（xray 26.x stream-one）：POST {path}/，Content-Type:
				// application/grpc（客户端默认带，除非显式禁用 NoGRPCHeader）。
				// 与 grpc 的区别在于路径无 /Tun 后缀。
				const isXhttp = !isGrpc && request.method === 'POST' && contentType.includes('application/grpc');
				if (upgrade === 'websocket' && !isGrpc && !isXhttp) {
					return await handleWebSocketUpgrade(request, config, env);
				}
				if (isGrpc) {
					return await handleGrpcInbound(request, config, env);
				}
				if (isXhttp) {
					return await handleXHTTPInbound(request, config, env);
				}
				// h2 入站：xray 的 http/h2 transport 默认 method=PUT（HTTP/2 prior knowledge），
				// 链接未显式带 method 时客户端一律发 PUT；同时兼容显式 POST 与
				// sing-box http transport 默认 method=GET 且 body 承载代理流的场景。
				// 缺失 PUT 会令 xray h2 请求落入下方伪装页，客户端收到 HTML 挂起超时。
				// 无 body 的普通 GET（浏览器/探测）不进代理，交下方订阅/伪装页处理
				if (request.method === 'POST' || request.method === 'PUT' || (request.method === 'GET' && request.body)) {
					return await handleH2Inbound(request, config, env);
				}
			}

			// 4) 订阅 / 配置页 / 伪装页
			return await handleHttp(request, config, env);
		} catch (e) {
			console.log(`[index] error: ${e.message || e}`);
			return new Response(JSON.stringify({ error: 'internal error' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json; charset=utf-8' }
			});
		}
	},

	/**
	 * Cron 定时触发
	 */
	async scheduled(event, env, ctx) {
		return scheduled(event, env, ctx);
	},

	/**
	 * Queue consumer：geo 更新队列（手动/定时触发入队后在此独立执行）
	 * - 独立执行窗口（默认最长 15 分钟），不受请求 30s wall-time 限制
	 * - 失败由队列自动重试（max_retries=2），耗尽后进死信队列
	 * - 完成/失败统一清理 geo:updating 锁并写进度，前端轮询 geo/status 展示
	 * @param {import('@cloudflare/workers-types').MessageBatch} batch
	 */
	async queue(batch, env, ctx) {
		for (const msg of batch.messages) {
			try {
				// 幂等保护：消费前先检查 geo:update_busy 标记，若已有更新任务在执行则直接 ack 跳过，
				// 防止任务未完成期间积压的重复消息各自触发一次全量（约 1589 分类）更新
				const busy = await env.GEO_KV.get('geo:update_busy');
				if (busy === '1') {
					console.log('[queue] geo update already in progress, skip message');
					msg.ack();
					continue;
				}
				await env.GEO_KV.put('geo:update_busy', '1', { expirationTtl: 7200 });
				try {
					// runGeoUpdateTask 内部会写分阶段进度到 geo:update_status 并清理 geo:updating 锁
					const detail = await runGeoUpdateTask(env.DB, env.GEO_KV);
					console.log(`[queue] geo update done: ${detail.updated}/${detail.total} categories${detail.failed.length ? ', failed: ' + detail.failed.join('; ') : ''}`);
					msg.ack();
				} finally {
					// 无论成功失败均清除 busy 标记，允许后续（重试/新入队）消息继续执行
					await env.GEO_KV.put('geo:update_busy', '0').catch(() => {});
				}
			} catch (e) {
				console.log(`[queue] geo update failed (will retry): ${e.message || e}`);
				// 抛错 → 队列按 max_retries 重试；重试耗尽自动进死信队列
				throw e;
			}
		}
	}
};
