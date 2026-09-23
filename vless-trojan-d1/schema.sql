-- vless-trojan-d1 D1 schema
-- 用法: wrangler d1 execute cf-vless-trojan-d1 --file=./schema.sql --remote

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS vless_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE NOT NULL,
  remark TEXT DEFAULT '',
  enable INTEGER DEFAULT 1,
  created_at INTEGER DEFAULT (unixepoch()),
  up INTEGER DEFAULT 0,
  down INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS trojan_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  password TEXT UNIQUE NOT NULL,
  remark TEXT DEFAULT '',
  enable INTEGER DEFAULT 1,
  created_at INTEGER DEFAULT (unixepoch()),
  up INTEGER DEFAULT 0,
  down INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('socks5','http','vless')),
  name TEXT UNIQUE NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  uuid TEXT DEFAULT '',
  path TEXT DEFAULT '',
  tls INTEGER DEFAULT 0,
  udp INTEGER DEFAULT 1,
  enable INTEGER DEFAULT 1,
  sort INTEGER DEFAULT 0,
  username TEXT DEFAULT '',
  password TEXT DEFAULT '',
  sni TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule TEXT NOT NULL,
  outbound TEXT NOT NULL,
  enable INTEGER DEFAULT 1,
  sort INTEGER DEFAULT 0
);

-- 种子：系统设置（admin_password_hash 由 Worker 首次启动自动生成，见 src/config/defaults.js）
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('ws_path', '/'),
  ('default_outbound', 'direct'),
  ('admin_password_hash', ''),
  ('admin_cookie_secret', ''),
  ('disguise_title', 'AList'),
  ('disguise_subtitle', '一个支持多存储的文件列表程序'),
  -- proxyip：访问 Cloudflare 及开启 Cloudflare CDN 网站使用的代理 IP（可填 IP 或域名，支持 [host]:port，默认 443）；仅默认出站为 direct 时生效
  ('proxyip', ''),
  -- udp_outbound：UDP 出站代理（出站名，仅 vless 支持 UDP）
  ('udp_outbound', ''),
  -- 入口设置：设置后节点/订阅生成使用入口配置，未设置则使用当前域名
  ('entry_host', ''),
  ('entry_port', ''),
  ('entry_sni', ''),
  ('entry_ws_host', '');

-- 种子：默认用户（部署后可进后台修改/删除）
INSERT OR IGNORE INTO vless_users (uuid, remark) VALUES
  ('86c50e3a-5b87-49dd-bd20-03c7f2735e40', 'default');

INSERT OR IGNORE INTO trojan_users (password, remark) VALUES
  ('trojan', 'default');

-- 旧库迁移（已部署旧版本时需手动执行；新建库执行本文件即可）
-- 1) outbounds 补充认证/SNI 字段：
-- ALTER TABLE outbounds ADD COLUMN username TEXT DEFAULT '';
-- ALTER TABLE outbounds ADD COLUMN password TEXT DEFAULT '';
-- ALTER TABLE outbounds ADD COLUMN sni TEXT DEFAULT '';
-- 2) 删除 proxyip 出站（proxyip 改为系统设置项，出站代理仅保留 socks5/http/vless）：
-- DELETE FROM outbounds WHERE type = 'proxyip';
-- 3) 删除已废弃的优选/CDN 设置项，补充新设置项：
-- DELETE FROM settings WHERE key IN ('cdnip','ip1','ip2','ip3','ip4','ip5','ip6','ip7','ip8','ip9','ip10','ip11','ip12','ip13','pt1','pt2','pt3','pt4','pt5','pt6','pt7','pt8','pt9','pt10','pt11','pt12','pt13');
-- INSERT OR IGNORE INTO settings (key, value) VALUES ('udp_outbound',''),('entry_host',''),('entry_port',''),('entry_sni',''),('entry_ws_host','');

-- 种子：默认分流规则（空表时不插，全部走默认出站）
