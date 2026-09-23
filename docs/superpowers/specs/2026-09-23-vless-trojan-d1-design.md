# vless-trojan-d1 全新架构设计

日期: 2026-09-23
状态: 已批准

## 目标

在 Cloudflare Workers 平台上重构 vless/trojan 代理项目：

1. 参考 3x-ui 提供苹果风格后台（`/admin`），配置存储从环境变量迁移到 D1 数据库
2. 参考 EDtunnel 实现自定义 ws 路径、多 UUID、SOCKS5/HTTP 出站、VLESS 出站完整 UDP 支持
3. 参考 xray 实现 geosite/geoip 分流（自动更新规则库），支持 `geosite:speedtest,google` 等标签语法
4. Alist 风格默认伪装页

## 决策记录

- 数据库：D1（SQLite），配置/规则/用户/流量统计全部入库
- KV（GEO_KV）：仅存放 geo 分类数据（dat 拆分 JSON），规避 25MB 单值限制
- 协议范围：vless + trojan 双入站并入新架构，后台分别管理
- 分流：规则列表匹配（域名规则优先）+ geoip 兜底，支持 xray 标签语法
- 后台功能：入站管理 / 出站代理管理 / 分流规则管理 / 节点与订阅生成 / 系统设置 / 流量统计（全量）
- 伪装页：Alist 风静态页
- 构建链：esbuild bundle + javascript-obfuscator，产出 `_worker.js`（混淆）+ `_worker明.js`（明码）
- 项目目录：`vless-trojan-d1/`（不动现有 Vless/Trojan/s5http 目录）

## 架构

单 Worker 统一入口，按优先级分发：

```
请求进入
 ├─ /admin 及 /admin/api/*        → 后台页面 + REST API（登录鉴权）
 ├─ /geo-update-cron              → Cron 触发 geo 库更新
 ├─ {ws_path} 精确匹配            → vless / trojan 入站处理
 ├─ /{uuid|password}              → 单节点配置页 / 订阅生成
 ├─ 其他                          → Alist 风伪装页（兜底）
```

目录结构：

```
vless-trojan-d1/
├── src/
│   ├── index.js          # 入口路由
│   ├── config/           # 常量 + D1 读取层
│   ├── db/               # schema 迁移 + 种子 + 查询层
│   ├── handlers/         # vless / trojan / ws
│   ├── outbound/         # direct / socks5 / http / vless
│   ├── routing/          # geo 分流引擎
│   ├── admin/            # 苹果风格后台（HTML/CSS/JS + API）
│   ├── generators/       # 节点链接 / 订阅生成
│   ├── disguise/         # Alist 风伪装页
│   └── cron.js           # geo 更新
├── package.json
├── wrangler.toml
├── schema.sql
└── README.md
```

## D1 表结构

- `settings(key PK, value, updated_at)`：admin 密码哈希、ws_path、default_outbound、proxyip、CDNIP、ip1-13/pt1-13、伪装页标题
- `vless_users(id, uuid UNIQUE, remark, enable, created_at, up, down)`
- `trojan_users(id, password UNIQUE, remark, enable, created_at, up, down)`
- `outbounds(id, type CHECK(socks5/http/vless), name, address, port, uuid, path, tls, udp, enable, sort)`
- `routing_rules(id, rule, outbound, enable, sort)`；outbound 取值 direct / reject / 出站 name

## KV 与 geo 更新

- 键：`geosite:{category}` / `geoip:{category}`（JSON 列表）、`geo:version`
- Cron（每天 3:00）读 routing_rules 引用分类 → 增量拉取上游（MetaCubeX/sing-geosite、sing-geoip json）→ 写 KV
- 冷启动懒加载 + 并发锁防击穿；后台手动更新按钮
- 域名匹配后缀 Map；CIDR 排序数组 + 二分

## 分流引擎

支持语法：`geosite:x`、`geosite:a,b`（或）、`geoip:x`、`domain:`、`full:`、`keyword:`、`ip-cidr:`、`regexp:`

- 按 sort 遍历启用规则；geoip 规则仅对 IP 型目标生效；未命中走 default_outbound
- UDP 同样分流，出站不支持 UDP 时回退默认 vless 出站或 direct

## 出站层

| 出站 | TCP | UDP |
|---|---|---|
| direct | connect 直连 | connect UDP（TURN） |
| socks5 | CONNECT | UDP ASSOCIATE 隧道 |
| http | CONNECT 隧道 | 不支持 → 回退 |
| vless | vless 握手 + 转发 | 完整 UDP over TCP |

## admin 后台

- PBKDF2 密码校验 + HMAC 签名 Cookie
- iOS 设置风格单页（纯 HTML/CSS/JS，无外部依赖）
- API：vless-users / trojan-users / outbounds / routing-rules CRUD；settings GET/PUT；stats；geo/update

## 流量统计

连接关闭时按 uuid/password 累加 up/down 写回 D1（ctx.waitUntil 异步落盘）。

## 构建与部署

- `npm run build`：esbuild + obfuscator → `_worker.js` + `_worker明.js`
- wrangler.toml：D1、GEO_KV、Cron
- 部署：登录 → 建 D1 → 建 KV → 灌 schema → build + deploy

## 测试

- routing 引擎单测（Node + mock KV）
- wrangler dev 本地联调
- 客户端实测（v2rayN / sing-box）
