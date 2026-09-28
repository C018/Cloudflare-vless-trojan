/**
 * Routing engine: rule parsing & matching
 * 支持语法：geosite:x,a | geoip:x | domain: | full: | keyword: | ip-cidr: | regexp:
 * 未指定前缀的裸字符串按 domain 后缀匹配（兼容 xray 语义）
 */

import { getGeoData } from './geo.js';

/**
 * 解析规则字符串
 * 结果按规则串缓存：decideRoute 每条规则在每个新连接上都会调用 parseRule，
 * 规则数多时重复正则解析成为纯 CPU 热点；缓存后 O(1) 命中（上限 512，超限清空重建）。
 * @param {string} ruleStr
 * @returns {{type:string, value:string, categories?:string[], _lcValue?:string}|null}
 */
const parsedRuleCache = new Map();
const PARSED_RULE_CACHE_MAX = 512;
export function parseRule(ruleStr) {
	if (!ruleStr) return null;
	let s = String(ruleStr).trim();
	if (!s) return null;
	if (parsedRuleCache.has(s)) return parsedRuleCache.get(s);
	let parsed = parseRuleUncached(s);
	// 预小写 value：匹配时域名/关键字比较都走小写，避免每次连接重复 toLowerCase 全串分配
	if (parsed && parsed.value) parsed._lcValue = parsed.value.toLowerCase();
	if (parsedRuleCache.size >= PARSED_RULE_CACHE_MAX) parsedRuleCache.clear();
	parsedRuleCache.set(s, parsed);
	return parsed;
}

function parseRuleUncached(s) {
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
 * IPv6 字符串 -> BigInt（支持 :: 压缩与方括号）
 */
function ipv6ToBigInt(ipv6) {
	const s = String(ipv6).replace(/^\[|\]$/g, '');
	const dbl = s.indexOf('::');
	let left, right;
	if (dbl >= 0) {
		left = dbl === 0 ? [] : s.slice(0, dbl).split(':');
		right = dbl === s.length - 2 ? [] : s.slice(dbl + 2).split(':');
	} else {
		left = s.split(':');
		right = [];
	}
	if (left.length + right.length > 8) return null;
	const missing = 8 - left.length - right.length;
	const groups = [...left, ...Array(missing).fill('0'), ...right];
	let n = 0n;
	for (const g of groups) {
		if (!g) return null;
		const v = parseInt(g, 16);
		if (isNaN(v)) return null;
		n = (n << 16n) | BigInt(v);
	}
	return n;
}

/**
 * CIDR 匹配（IPv4 / IPv6 双栈）
 * @param {string} ipAddr
 * @param {string} cidr
 */
function matchCidr(ipAddr, cidr) {
	const slash = cidr.indexOf('/');
	const base = slash >= 0 ? cidr.slice(0, slash) : cidr;
	const defaultPrefix = ipAddr.includes(':') ? 128 : 32;
	const prefix = slash >= 0 ? Number(cidr.slice(slash + 1)) : defaultPrefix;
	if (ipAddr.includes(':')) {
		const ip = ipv6ToBigInt(ipAddr);
		const baseInt = ipv6ToBigInt(base);
		if (ip === null || baseInt === null || isNaN(prefix) || prefix < 0 || prefix > 128) return false;
		const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
		return (ip & mask) === (baseInt & mask);
	}
	const ipInt = ipv4ToInt(ipAddr);
	if (ipInt === null) return false;
	const baseInt = ipv4ToInt(base);
	if (baseInt === null) return false;
	const mask = prefix <= 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return (ipInt & mask) === (baseInt & mask);
}

/**
 * 域名后缀匹配（含子域名）。入参须已小写化（调用方预小写一次，避免每次比较全串扫描分配）。
 * 语义与原实现等价：精确相等或以后缀结尾（'xabc.com' 命中 'abc.com' 的宽松匹配保留），
 * 原 'h.endsWith("." + d)' 分支已被 'h.endsWith(d)' 覆盖（以 '.d' 结尾必然以 'd' 结尾），
 * 去掉可省每次比较的 '.'+d 字符串拼接分配。
 */
function matchDomain(lcHost, lcDomain) {
	if (lcHost === lcDomain) return true;
	return lcHost.endsWith(lcDomain);
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
	// 域名类规则共用一次小写化（domain/full/keyword 与 geosite 循环均复用），
	// 避免每条规则、每个候选域各做一次全串 toLowerCase 分配
	const lcHost = isIP ? '' : addressRemote.toLowerCase();
	switch (parsed.type) {
		case 'domain': {
			if (isIP) return false;
			return matchDomain(lcHost, parsed._lcValue);
		}
		case 'full': {
			if (isIP) return false;
			return lcHost === parsed._lcValue;
		}
		case 'keyword': {
			if (isIP) return false;
			return lcHost.includes(parsed._lcValue);
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
					if (matchDomain(lcHost, d)) return true;
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
