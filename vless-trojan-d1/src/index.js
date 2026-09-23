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

import { createRequestConfig } from './config/defaults.js';
import { handleWebSocketUpgrade } from './handlers/websocket.js';
import { handleHttp } from './handlers/http.js';
import { handleAdminApi } from './admin/api.js';
import { buildAdminUI } from './admin/ui.js';
import { handleCron, scheduled } from './cron.js';

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
					return await handleAdminApi(request, config);
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

			// 3) WebSocket 代理入站（ws_path 精确匹配）
			const config = await createRequestConfig(request, env);
			if (path === config.wsPath) {
				return await handleWebSocketUpgrade(request, config, env);
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
	}
};
