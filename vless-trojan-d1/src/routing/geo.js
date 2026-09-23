/**
 * Geo data loader: KV-backed with instance cache and builtin bootstrap
 */

import {
	GEO_KV_PREFIX_GEOSITE, GEO_KV_PREFIX_GEOIP,
	BOOTSTRAP_GEOSITE_CN, BOOTSTRAP_GEOSITE_SPEEDTEST, BOOTSTRAP_GEOSITE_GOOGLE
} from '../config/constants.js';

const CACHE_TTL_MS = 60 * 60 * 1000; // 1h
const cache = new Map(); // key: geosite:cn / geoip:cn -> {data, ts}

/**
 * @param {Object} env
 * @param {'geosite'|'geoip'} type
 * @param {string} category
 * @returns {Promise<string[]>} 域名后缀列表 / CIDR 列表
 */
export async function getGeoData(env, type, category) {
	const key = `${type}:${category}`;
	const cached = cache.get(key);
	if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
		return cached.data;
	}

	let data = null;
	try {
		const prefix = type === 'geosite' ? GEO_KV_PREFIX_GEOSITE : GEO_KV_PREFIX_GEOIP;
		const raw = await env.GEO_KV.get(prefix + category);
		if (raw) {
			const parsed = JSON.parse(raw);
			if (Array.isArray(parsed)) data = parsed;
		}
	} catch (e) { /* ignore */ }

	if (!data) {
		data = bootstrap(type, category);
	}
	cache.set(key, { data, ts: Date.now() });
	return data;
}

function bootstrap(type, category) {
	if (type === 'geosite') {
		switch (category) {
			case 'cn': return BOOTSTRAP_GEOSITE_CN;
			case 'speedtest': return BOOTSTRAP_GEOSITE_SPEEDTEST;
			case 'google': return BOOTSTRAP_GEOSITE_GOOGLE;
			default: return [];
		}
	}
	// geoip 冷启动无内置数据，空数组
	return [];
}

export function clearGeoCache() {
	cache.clear();
}
