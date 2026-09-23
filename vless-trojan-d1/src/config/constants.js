/**
 * vless-trojan-d1 constants
 */

// ---- VLESS protocol ----
export const VLESS_CMD_TCP = 0x01;
export const VLESS_CMD_UDP = 0x02;
export const VLESS_CMD_MUX = 0x03;

export const VLESS_ADDR_IPV4 = 1;
export const VLESS_ADDR_DOMAIN = 2;
export const VLESS_ADDR_IPV6 = 3;

// ---- Trojan protocol ----
export const TROJAN_CMD_TCP = 0x01;
export const TROJAN_CMD_UDP = 0x03;
// Trojan atyp: 1=IPv4 3=Domain 4=IPv6

// ---- WebSocket ready states ----
export const WS_READY_STATE_CONNECTING = 0;
export const WS_READY_STATE_OPEN = 1;
export const WS_READY_STATE_CLOSING = 2;
export const WS_READY_STATE_CLOSED = 3;

// ---- Outbound types ----
export const OUTBOUND_DIRECT = 'direct';
export const OUTBOUND_REJECT = 'reject';
export const OUTBOUND_SOCKS5 = 'socks5';
export const OUTBOUND_HTTP = 'http';
export const OUTBOUND_VLESS = 'vless';

// ---- Geo keys ----
export const GEO_KV_PREFIX_GEOSITE = 'geosite:';
export const GEO_KV_PREFIX_GEOIP = 'geoip:';
export const GEO_KV_VERSION = 'geo:version';

// ---- Admin cookie ----
export const ADMIN_COOKIE_NAME = 'vtd_admin';
export const ADMIN_COOKIE_MAX_AGE = 86400 * 7; // 7 days

// ---- Default ws path ----
export const DEFAULT_WS_PATH = '/ws';

// ---- D1 table names ----
export const TABLE_SETTINGS = 'settings';
export const TABLE_VLESS_USERS = 'vless_users';
export const TABLE_TROJAN_USERS = 'trojan_users';
export const TABLE_OUTBOUNDS = 'outbounds';
export const TABLE_ROUTING_RULES = 'routing_rules';

// ---- Builtin geo bootstrap (fallback when KV empty / update failed) ----
// 内置最小 geosite 分类：cn 常用国内域名后缀，用于冷启动兜底
export const BOOTSTRAP_GEOSITE_CN = [
	'qq.com', 'taobao.com', 'tmall.com', 'jd.com', 'baidu.com', 'bilibili.com',
	'douyin.com', 'weibo.com', 'zhihu.com', '163.com', '126.com', 'aliyun.com',
	'tencent.com', 'weixin.qq.com', 'alipay.com', 'bankofchina.com', 'icbc.com.cn',
	'ccb.com', 'abcchina.com', 'cmbchina.com', 'boc.cn', '12306.cn', 'gov.cn',
	'cn', 'com.cn', 'net.cn', 'org.cn'
];
export const BOOTSTRAP_GEOSITE_SPEEDTEST = [
	'speedtest.net', 'fast.com', 'ookla.com'
];
export const BOOTSTRAP_GEOSITE_GOOGLE = [
	'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
	'ggpht.com', 'google.cn', 'google.com.hk', 'gvt1.com', 'gvt2.com', 'gvt3.com'
];

// ---- hex lookup for uuid stringify ----
export const byteToHex = [];
for (let n = 0; n <= 0xff; ++n) {
	const hexOctet = n.toString(16).padStart(2, '0');
	byteToHex.push(hexOctet);
}
