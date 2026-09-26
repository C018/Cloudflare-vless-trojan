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
export { ProxySessionDO } from './durable/session-do.js';
import { handleH2Inbound, handleGrpcInbound } from './handlers/entry.js';
import { handleHttp } from './handlers/http.js';
import { handleAdminApi, runGeoUpdateTask } from './admin/api.js';
import { buildAdminUI } from './admin/ui.js';
import { handleCron, scheduled } from './cron.js';

// Workers 平台 Socket 建连能力注入：direct / proxyip / socks5 / http 出站均依赖 globalThis.connect
globalThis.connect = connect;

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
				return new Response(buildAdminUI(config.adminTempPassword), {
					headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
				});
			}

			// 2) Cron geo 更新
			if (path === '/geo-update-cron') {
				return await handleCron(request, env);
			}

			// 3) 代理入站：按入站路径映射 + 请求特征自动分发（同一凭据同时支持 ws / grpc / h2）
			const config = await createRequestConfig(request, env);
			const scopes = config.inboundPathMap.get(path);
			if (scopes && scopes.length > 0) {
				config._inboundScope = composeInboundScope(scopes);
				const upgrade = String(request.headers.get('Upgrade') || '').toLowerCase();
				const contentType = String(request.headers.get('Content-Type') || '').toLowerCase();
				const isGrpc = path.endsWith('/Tun') || contentType.includes('application/grpc');
				if (upgrade === 'websocket' && !isGrpc) {
					// DO 托管长连接会话，突破 30s idle 断连；未配置 DO binding 时回退 Worker 内处理
					if (env.PROXY_DO) {
						const doId = env.PROXY_DO.idFromUniqueId(crypto.randomUUID());
						return await env.PROXY_DO.get(doId).fetch(request);
					}
					return await handleWebSocketUpgrade(request, config, env);
				}
				if (isGrpc) {
					return await handleGrpcInbound(request, config, env);
				}
				// h2 入站客户端以 POST 建立（HTTP/2 请求）；GET 等普通请求交给订阅/伪装页
				if (request.method === 'POST') {
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
				// runGeoUpdateTask 内部会写分阶段进度到 geo:update_status 并清理 geo:updating 锁
				const detail = await runGeoUpdateTask(env.DB, env.GEO_KV);
				console.log(`[queue] geo update done: ${detail.updated}/${detail.total} categories${detail.failed.length ? ', failed: ' + detail.failed.join('; ') : ''}`);
				msg.ack();
			} catch (e) {
				console.log(`[queue] geo update failed (will retry): ${e.message || e}`);
				// 抛错 → 队列按 max_retries 重试；重试耗尽自动进死信队列
				throw e;
			}
		}
	}
};
