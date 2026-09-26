/**
 * Routing engine: rule parsing & matching
 * 支持语法：geosite:x,a | geoip:x | domain: | full: | keyword: | ip-cidr: | regexp:
 * 未指定前缀的裸字符串按 domain 后缀匹配（兼容 xray 语义）
 */

import { getGeoData } from './geo.js';

/**
 * 解析规则字符串
 * @param {string} ruleStr
 * @returns {{type:string, value:string, categories?:string[]}|null}
 */
export function parseRule(ruleStr) {
	if (!ruleStr) return null;
	let s = String(ruleStr).trim();
	if (!s) return null;

	// 多 geosite 分类逗号分隔
	const geositeMatch = s.match(/^geosite:(.+)$/i);
	if (geositeMatch) {
		const categories = geositeMatch[1].split(',').map((x) => x.trim()).filter(Boolean);
		if (categories.length === 0) return null;
		return { type: 'geosite', categories };
	}
	const geoipMatch = s.match(/^geoip:(.+)$/i);
	if (geoipMatch) {
		const categories = geoipMatch[1].split(',').map((x) => x.trim()).filter(Boolean);
		if (categories.length === 0) return null;
		return { type: 'geoip', categories };
	}
	const domainMatch = s.match(/^domain:(.+)$/i);
	if (domainMatch) return { type: 'domain', value: domainMatch[1].trim() };
	const fullMatch = s.match(/^full:(.+)$/i);
	if (fullMatch) return { type: 'full', value: fullMatch[1].trim() };
	const keywordMatch = s.match(/^keyword:(.+)$/i);
	if (keywordMatch) return { type: 'keyword', value: keywordMatch[1].trim() };
	const ipcidrMatch = s.match(/^ip-cidr:(.+)$/i);
	if (ipcidrMatch) return { type: 'ip-cidr', value: ipcidrMatch[1].trim() };
	const regexpMatch = s.match(/^regexp:(.+)$/i);
	if (regexpMatch) return { type: 'regexp', value: regexpMatch[1].trim() };

	// 裸字符串 → domain 后缀
	return { type: 'domain', value: s };
}

/**
 * IPv4 字符串 -> 数值
 */
function ipv4ToInt(ip) {
	const parts = ip.split('.');
	if (parts.length !== 4) return null;
	let n = 0;
	for (const p of parts) {
		const oct = Number(p);
		if (isNaN(oct) || oct < 0 || oct > 255) return null;
		n = (n << 8) | oct;
	}
	return n >>> 0;
}

/**
 * CIDR 匹配（仅 IPv4；IPv6 目标跳过 ip-cidr）
 * @param {string} ipAddr
 * @param {string} cidr
 */
function matchCidr(ipAddr, cidr) {
	const [base, prefixStr] = cidr.split('/');
	const prefix = prefixStr !== undefined ? Number(prefixStr) : 32;
	const ipInt = ipv4ToInt(ipAddr);
	if (ipInt === null) return false; // IPv6 or invalid
	const baseInt = ipv4ToInt(base);
	if (baseInt === null) return false;
	const mask = prefix <= 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return (ipInt & mask) === (baseInt & mask);
}

/**
 * 域名后缀匹配（含子域名）
 */
function matchDomain(hostname, domain) {
	const h = hostname.toLowerCase();
	const d = domain.toLowerCase();
	if (h === d) return true;
	return h.endsWith('.' + d) || h.endsWith(d);
}

const regexCache = new Map();
function getRegex(pattern) {
	let re = regexCache.get(pattern);
	if (!re) {
		try { re = new RegExp(pattern); } catch (e) { re = null; }
		regexCache.set(pattern, re);
	}
	return re;
}

/**
 * 匹配单条已解析规则
 * @param {Object} parsed parseRule 结果
 * @param {string} addressRemote 目标（域名或 IP 字符串）
 * @param {boolean} isIP 目标是否为 IP
 * @param {Object} env
 */
export async function matchParsedRule(parsed, addressRemote, isIP, env) {
	switch (parsed.type) {
		case 'domain': {
			if (isIP) return false;
			return matchDomain(addressRemote, parsed.value);
		}
		case 'full': {
			if (isIP) return false;
			return addressRemote.toLowerCase() === parsed.value.toLowerCase();
		}
		case 'keyword': {
			if (isIP) return false;
			return addressRemote.toLowerCase().includes(parsed.value.toLowerCase());
		}
		case 'regexp': {
			if (isIP) return false;
			const re = getRegex(parsed.value);
			return re ? re.test(addressRemote) : false;
		}
		case 'ip-cidr': {
			if (!isIP) return false;
			return matchCidr(addressRemote, parsed.value);
		}
		case 'geosite': {
			if (isIP) return false;
			for (const category of parsed.categories) {
				const domains = await getGeoData(env, 'geosite', category);
				for (const d of domains) {
					if (matchDomain(addressRemote, d)) return true;
				}
			}
			return false;
		}
		case 'geoip': {
			if (!isIP) return false;
			for (const category of parsed.categories) {
				const cidrs = await getGeoData(env, 'geoip', category);
				for (const cidr of cidrs) {
					if (matchCidr(addressRemote, cidr)) return true;
				}
			}
			return false;
		}
		default:
			return false;
	}
}

/**
 * 分流决策
 * @param {Object} config 请求级配置
 * @param {number} addressType 1=IPv4 2=Domain 3=IPv6
 * @param {string} addressRemote
 * @returns {Promise<{outbound:string, rule:Object|null}>} outbound: direct/reject/出站名
 */
const ROUTE_CACHE_TTL = 60_000;
const ROUTE_CACHE_MAX = 10_000;
const routeCache = new Map(); // `${addressType}:${domain/ip小写}` -> { outbound, rule, ts }

export async function decideRoute(config, addressType, addressRemote) {
	const cacheKey = `${addressType}:${addressRemote.toLowerCase()}`;
	const hit = routeCache.get(cacheKey);
	if (hit && Date.now() - hit.ts < ROUTE_CACHE_TTL) {
		return { outbound: hit.outbound, rule: hit.rule };
	}
	const isIP = addressType === 1 || addressType === 3;
	let outbound = config.defaultOutbound || 'direct';
	let rule = null;
	for (const r of config.routingRules) {
		const parsed = parseRule(r.rule);
		if (!parsed) continue;
		const h = await matchParsedRule(parsed, addressRemote, isIP, config.env);
		if (h) {
			outbound = r.outbound || 'direct';
			rule = r;
			break;
		}
	}
	if (routeCache.size >= ROUTE_CACHE_MAX) routeCache.clear();
	routeCache.set(cacheKey, { outbound, rule, ts: Date.now() });
	return { outbound, rule };
}
