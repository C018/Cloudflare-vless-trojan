/**
 * Cron handler: scheduled geo database update (daily 03:00)
 */

import { updateGeo } from './admin/api.js';

/**
 * @param {import('@cloudflare/workers-types').Request} request
 * @param {Object} env
 * @returns {Promise<Response>}
 */
export async function handleCron(request, env) {
	// 安全校验：允许裸触发（wrangler 定时）或携带自定义 secret
	const url = new URL(request.url);
	if (request.method === 'POST' || request.method === 'GET') {
		try {
			const { DB, GEO_KV } = env;
			const detail = await updateGeo(DB, GEO_KV);
			return new Response(JSON.stringify({ ok: true, updated: detail.updated, total: detail.total, failed: detail.failed }), {
				status: 200,
				headers: { 'Content-Type': 'application/json; charset=utf-8' }
			});
		} catch (e) {
			return new Response(JSON.stringify({ ok: false, error: e.message }), {
				status: 500,
				headers: { 'Content-Type': 'application/json; charset=utf-8' }
			});
		}
	}
	return new Response('Not Found', { status: 404 });
}

/**
 * Scheduled event handler (wrangler cron trigger)
 * @param {Object} event {scheduledTime, cron}
 * @param {Object} env
 * @param {Object} ctx
 */
export async function scheduled(event, env, ctx) {
	try {
		const detail = await updateGeo(env.DB, env.GEO_KV);
		console.log(`[cron] geo update done: ${detail.updated}/${detail.total} categories${detail.failed.length ? ', failed: ' + detail.failed.join('; ') : ''}`);
	} catch (e) {
		console.log(`[cron] geo update failed: ${e.message}`);
	}
}
