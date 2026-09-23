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
  sort INTEGER DEFAULT 0
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
  ('proxyip', ''),
  ('cdnip', ''),
  ('ip1', 'www.visa.com.sg'), ('ip2', 'cis.visa.com'), ('ip3', 'africa.visa.com'),
  ('ip4', 'www.visa.com.sg'), ('ip5', 'www.visaeurope.at'), ('ip6', 'www.visa.com.mt'),
  ('ip7', 'qa.visamiddleeast.com'), ('ip8', 'usa.visa.com'), ('ip9', 'myanmar.visa.com'),
  ('ip10', 'www.visa.com.tw'), ('ip11', 'www.visaeurope.ch'), ('ip12', 'www.visa.com.br'),
  ('ip13', 'www.visasoutheasteurope.com'),
  ('pt1', '80'), ('pt2', '8080'), ('pt3', '8880'), ('pt4', '2052'), ('pt5', '2082'),
  ('pt6', '2086'), ('pt7', '2095'), ('pt8', '443'), ('pt9', '8443'), ('pt10', '2053'),
  ('pt11', '2083'), ('pt12', '2087'), ('pt13', '2096');

-- 种子：默认用户（部署后可进后台修改/删除）
INSERT OR IGNORE INTO vless_users (uuid, remark) VALUES
  ('86c50e3a-5b87-49dd-bd20-03c7f2735e40', 'default');

INSERT OR IGNORE INTO trojan_users (password, remark) VALUES
  ('trojan', 'default');

-- 种子：默认出站（proxyip 语义并入出站管理）
INSERT OR IGNORE INTO outbounds (type, name, address, port, udp, sort) VALUES
  ('socks5', 'proxyip', 'pyip.ygkkk.dpdns.org', 443, 1, 0);

-- 种子：默认分流规则（空表时不插，全部走默认出站）
