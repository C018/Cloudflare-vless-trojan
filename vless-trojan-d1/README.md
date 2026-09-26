# vless-trojan-d1

基于 Cloudflare Workers + D1 + KV 的 VLESS / Trojan 双协议代理面板，单文件部署（`_worker.js` 混淆版 / `_worker明.js` 明码版）。

## 功能特性

- VLESS / Trojan 双入站，多 UUID / 多密码，独立启停
- 分流引擎：`geosite:` / `geoip:` / `domain:` / `full:` / `keyword:` / `ip-cidr:` / `regexp:`，规则排序匹配
- 出站：direct / socks5 / http / vless（vless 支持完整 UDP），规则未命中走默认出站；direct 出站配 proxyip 时支持双向智能回退（直连 5s 无首包自动改走 proxyIP，proxyIP 无响应标记故障并回退直连，CF 相关站点访问更稳定）
- 系统设置：proxyip（CF 代理 IP，可填 IP 或域名，仅默认出站为 direct 时生效）、udp 出站代理（出站名，仅 vless 支持 UDP）
- 入口设置：可配置入口 IP/域名、端口、SNI、Host，设置后节点/订阅改用入口配置，未设置则使用当前域名
- 出站认证：socks5 / http 支持用户名密码认证（后台字段配置，或地址内嵌 `user:pass@host:port`，字段优先）
- VLESS 出站：支持 TLS（ws/wss 切换）与 SNI 配置（Workers 平台限制下 SNI 跟随连接主机名，配置 SNI 后以其作为连接主机）
- Geo 数据：GEO_KV 存分类 JSON，Cron 每日 03:00 自动更新（HTTP 可手动触发），内置冷启动兜底；手动更新经 Workers Queues 异步执行（不受请求 30s 限制，失败自动重试），后台弹窗轮询 `/admin/api/geo/status` 实时展示逐分类进度（进度状态写 GEO_KV 的 `geo:update_status`，已修复入队后空状态显示 0/0 的问题）
- 订阅生成：单节点 / 聚合（纯文本 / Base64 / Clash / sing-box）
- 单凭据配置页：`/uuid=<uuid>` 与 `/password=<密码>` 返回专属节点链接
- 网络状态检测：后台「网络状态」页按项目出站链（分流规则 + 默认出站 + proxyip + 出站隧道）在 Worker 内多目标并行探测，每目标 16 次采样，展示延迟 / 丢包 / min / max；ip.skk.moe 风格卡片，品牌色 Logo 与呼吸灯，支持自动刷新
- 运行时放置位置检测：后台「网络状态」页顶部新增运行时位置条（页面加载自动请求），展示当前请求实际处理的数据中心信息（`cf.colo` 三字码、CF 区域、城市/国家、入口域名、配置放置区域），API 端点为 `GET /admin/api/colo`（与现有 admin 鉴权一致，PBKDF2 + HMAC Cookie），用于确认区域放置（placement `region=gcp:asia-east2`）是否生效，排查请求被调度到非预期区域导致的延迟问题
- 后台：iOS 风格管理面板（流量统计、入站 / 出站 / 规则 / 设置管理、网络状态检测），PBKDF2 + HMAC Cookie 鉴权；移动端侧边栏自动改为底部横向滑动导航
- 伪装页：内嵌静态仿 Alist 文件列表页，无外部依赖
- DO 长连接改造：WS 入站代理会话已托管到 Durable Object（`ProxySessionDO`），突破 Workers 请求 30s idle 断连限制（Telegram 等长连接不再「正在刷新」）。技术要点：DO 内 `state.acceptWebSocket` 接管握手、`fetch` 立即返回 101，`processProxySession` 作为后台任务持续运行保持长连接（出站转发 / 流量统计与 Worker 内路径完全一致）；WS 消息经 Hibernation API 的 `webSocketMessage` 类方法接收（DO 中 `addEventListener('message')` 不生效）并注入 io 队列。`wrangler.toml` 增加 `[durable_objects]` 绑定 `PROXY_DO`（class_name=`ProxySessionDO`）与 `[[migrations]] new_sqlite_classes`；DO class 须从入口 `index.js` 具名导出（`export { ProxySessionDO }`）。未配置 DO 绑定（如手工粘贴部署漏配）时自动回退 Worker 内处理，不影响功能
- 代理超时修复：此前客户端连上但实际网络不可用（显示超时），根因是 webSocketMessage 回发的 `DIAG-SEND-OK` 诊断帧污染 VLESS 协议流——xray 校验响应首字节须为 `0x00`，收到 `'D'` 即报错/挂起。已移除 `proxy-session.js` / `session-do.js` 内的 DIAG-SEND-OK 测试帧（不再向客户端回发任何诊断帧；VLESS 握手响应 `0x00 0x00` 与 15s 空包心跳属协议必需，予以保留）
- DoH 多源修复（1.0.31）：未知域名（如 ip.sb、ip.skk.moe 等开启 CF CDN 的站点）先经 DoH 预解析，判定解析出的 IP 是否落 Cloudflare 地址段——命中则按 CF 站点走 proxyip，避免 sockets 直连 CF IP 被拦截后只能靠 5s 首包回退（慢且偶发失败）。`resolveViaDoH` 端点已从仅 Google IP 型（`https://8.8.8.8/resolve`、`https://8.8.4.4/resolve`）扩为 5 源：cloudflare-dns.com/dns-query、dns.alidns.com/resolve、doh.pub/resolve 域名型优先 + Google IP 型兜底，解决 Worker 运行时 IP 型 DoH 不可达导致预解析失败、路由测试与真实出站错误回退 direct 直连被拦的问题；DoH 结果缓存 300s，避免每个新连接重复查询拖慢建连
- 流量统计：连接关闭后异步写 D1，按 UUID / 密码维度计数

## 目录结构

```
vless-trojan-d1/
├── src/
│   ├── index.js            # 入口路由（admin / cron / queue / ws / 订阅 / 伪装页）+ 具名导出 ProxySessionDO
│   ├── cron.js             # 定时更新 Geo 数据
│   ├── netprobe.js         # 网络状态探测（Worker 内多目标并行采样）
│   ├── version.js          # 构建版本号（build.mjs 自动递增）
│   ├── config/
│   │   ├── constants.js    # 协议 / 出站 / geo 常量
│   │   └── defaults.js     # D1 读取层 + 请求级配置缓存 + 初始密码生成
│   ├── durable/
│   │   └── session-do.js   # Durable Object ProxySessionDO（长连接托管 / Hibernation API）
│   ├── handlers/
│   │   ├── entry.js        # 入站入口分流（ws / http 升级判断）
│   │   ├── http.js         # HTTP 入口处理
│   │   ├── websocket.js    # WS 升级 + io 适配（early data / createWsIO / feed 注入）
│   │   └── proxy-session.js# 通用代理会话核心（协议解析 / TCP / UDP 转发 / 流量统计）
│   ├── protocol/
│   │   ├── vless.js        # VLESS 入站头解析 / 出站头构造
│   │   └── trojan.js       # Trojan 入站头解析（SHA224 密码比对）
│   ├── outbound/
│   │   ├── stream.js       # WebSocket 流工具
│   │   ├── socks5.js       # SOCKS5 出站
│   │   ├── http.js         # HTTP CONNECT 出站
│   │   ├── vless.js        # VLESS 出站（ws 隧道，TCP/UDP）
│   │   ├── vless-grpc.js   # VLESS 出站（grpc 传输）
│   │   ├── vless-h2.js     # VLESS 出站（h2 传输）
│   │   ├── vless-httpupgrade.js # VLESS 出站（httpupgrade 传输）
│   │   ├── vless-raw.js    # VLESS 出站（raw / 原生 TCP）
│   │   ├── udp.js          # UDP 帧拆组
│   │   └── tcp.js          # TCP 出站调度（direct / proxyip 回退）
│   ├── routing/
│   │   ├── geo.js          # Geo 数据加载（KV + 缓存 + 兜底）
│   │   └── engine.js       # 分流规则解析与匹配
│   ├── admin/
│   │   ├── auth.js         # PBKDF2 密码哈希 + HMAC 会话
│   │   ├── api.js          # REST API（登录 / CRUD / 统计 / geo 更新 / 网络状态检测 / 路由测试）
│   │   └── ui.js           # 后台单页 UI（geo 进度弹框、网络状态页、出站路由测试）
│   ├── generators/
│   │   ├── subscription.js # 节点链接 / 订阅生成
│   │   └── config-page.js  # 单凭据配置页
│   └── disguise/
│       └── alist.js        # Alist 风格伪装页
├── schema.sql              # D1 建表与种子数据
├── wrangler.toml           # Worker / D1 / KV / Cron / Queues / Durable Objects 绑定
├── package.json            # 构建链（esbuild + javascript-obfuscator）
├── _worker.js              # 混淆版部署产物
└── _worker明.js            # 明码版部署产物
```

## 出站代理配置

后台「出站代理」页可管理 `socks5` / `http` / `vless` 三种出站，通过「分流规则」将匹配流量路由到指定出站。

| 类型 | 必填字段 | 可选字段 | 说明 |
|---|---|---|---|
| socks5 | address, port | username, password | 支持用户名密码认证；也可在地址内嵌 `user:pass@host:port`，后台字段优先 |
| http | address, port | username, password | HTTP CONNECT 代理，认证以 `Proxy-Authorization: Basic` 发送；同样支持地址内嵌凭据 |
| vless | address, port, uuid | path, tls, sni | 基于 WebSocket 隧道，支持完整 TCP/UDP；`tls` 开启后使用 wss；`sni` 指定 TLS 连接主机名（Workers 平台限制：SNI 跟随连接主机名，配置 SNI 后以 SNI 作为连接主机） |

> proxyip 已从出站类型改为系统设置项：在后台「系统设置」填写 proxyip（IP 或域名，支持 `host:port`，默认 443），当默认出站为 `direct` 时生效——目标端点替换为 proxyip 后裸 TCP 连接，客户端 TLS ClientHello / HTTP 首包原样转发，由 CF 边缘按 SNI / Host 路由，用于访问 Cloudflare 相关网站。UDP 出站代理在「系统设置」配置 `udp_outbound`（出站名，仅 vless 类型出站支持 UDP）。
>
> 1.0.8 起 direct + proxyip 支持双向智能回退：命中 Cloudflare 自家域名后缀时优先直连，其余目标默认直连，5s 内无首包数据自动回退 proxyIP 重连（仅 443 TLS 流量适用）；反之已走 proxyIP 的连接若 5s 无首包，会将该 proxyIP 标记为故障（60s 冷却期内同类连接直接改直连）并自动切回直连重试，CF 相关站点打开更稳定。

## 部署步骤

### 1. 创建 D1 数据库并导入表结构

```bash
wrangler d1 create vless-trojan-d1
# 将返回的 database_id 填入 wrangler.toml
wrangler d1 execute vless-trojan-d1 --remote --file=schema.sql
```

### 2. 创建 KV 命名空间

```bash
wrangler kv namespace create GEO_KV
# 将返回的 id 填入 wrangler.toml
```

### 3. 创建 Workers Queues 队列

```bash
wrangler queue create cf-vless-trojan-d1-geo-update
wrangler queue create cf-vless-trojan-d1-geo-update-dlq   # 死信队列
# 生产 / 消费绑定已在 wrangler.toml 中声明
```

> 部署前必须先创建上述两个队列：`wrangler.toml` 已声明 producer/consumer 绑定，但队列资源需提前在账号中创建，否则 `wrangler deploy` 会因队列不存在而报错。

### 4. 部署

```bash
npm install
npm run build        # 生成 _worker.js（混淆）与 _worker明.js（明码）
wrangler deploy
```

> Durable Objects：`wrangler.toml` 已声明 `[durable_objects]` 绑定 `PROXY_DO`（class_name=`ProxySessionDO`）与 `[[migrations]] new_sqlite_classes=["ProxySessionDO"]`，无需额外配置；首次 `wrangler deploy` 会自动执行 migration 创建 DO SQLite 类。**必须保留入口 `index.js` 对 `ProxySessionDO` 的具名导出**，否则 DO 类无法被 Worker 识别、WS 会话将回退 Worker 内处理（功能可用但无长连接保活）。

部署后可删除 `_worker明.js` 仅保留混淆版，降低被逆向概率。

## 单文件手动部署（控制台操作，免本地环境）

不依赖 Node.js / npm / wrangler CLI，全程在 Cloudflare 控制台完成。以下操作与 `wrangler deploy` 等效，绑定变量名与 `wrangler.toml` 保持一致（D1 绑定名 `DB`、KV 绑定名 `GEO_KV`、Queues 绑定名 `GEO_QUEUE`、Durable Object 绑定名 `PROXY_DO`）。

### 1. 创建 D1 数据库并建表

1. 打开 Cloudflare Dashboard → **Workers & Pages** → **D1** → **Create database**，命名为 `cf-vless-trojan-d1`。
2. 进入刚创建的数据库 → **Console**，将仓库内 `schema.sql` 的完整内容粘贴进去执行（建表与种子数据一次性完成）。

### 2. 创建 KV 命名空间

**Workers & Pages** → **KV** → **Create a namespace**，命名为 `GEO_KV`。

### 3. 创建 Workers Queues 队列

**Workers & Pages** → **Queues** → **Create queue**，分别创建 `cf-vless-trojan-d1-geo-update` 与死信队列 `cf-vless-trojan-d1-geo-update-dlq`。

### 4. 创建 Worker 并粘贴代码

1. **Workers & Pages** → **Create application** → **Worker**，命名为 `cf-vless-trojan-d1`。
2. 用编辑器打开本地 `_worker.js`（混淆版部署产物），**全选复制全部内容**，在 Worker 编辑器中覆盖默认模板代码。
3. 点击 **Deploy** 完成首次部署。

### 5. 绑定 D1、KV、Queues 与 Durable Objects

1. Worker 页面 → **Settings** → **Bindings** → **Add binding**：
   - **D1 database**：Variable name 填 `DB`，数据库选择 `cf-vless-trojan-d1`；
   - **KV namespace**：Variable name 填 `GEO_KV`，命名空间选择 `GEO_KV`；
   - **Queue（Producer）**：Variable name 填 `GEO_QUEUE`，队列选择 `cf-vless-trojan-d1-geo-update`。
2. 同一页面再添加 **Queue（Consumer）** 绑定：队列选择 `cf-vless-trojan-d1-geo-update`，批大小 1、最大重试 2、死信队列 `cf-vless-trojan-d1-geo-update-dlq`。
3. **添加 Durable Object 绑定**：**Add binding** → **Durable Object Namespace**，Variable name 填 `PROXY_DO`，Class name 填 `ProxySessionDO`（须与 `src/durable/session-do.js` 导出的类名一致）。
4. **添加 Durable Object migration**：Worker 页面 → **Settings** → **Durable Objects** → **Add migration**，选择 **New SQLite classes（new_sqlite_classes）**，类名填 `ProxySessionDO`，tag 可填 `v1`（对应 `wrangler.toml` 的 `[[migrations]]`）。控制台手动部署没有 wrangler CLI 自动迁移，漏配 migration 会导致 DO 类未创建、绑定不生效。
5. 保存绑定后再次点击 **Deploy**，使绑定生效（含 DO 绑定与 migration）。

> ⚠️ **重要踩坑（控制台手动部署）**：务必在 **Settings → Bindings** 中手动添加 **Queue（Producer）** 绑定 `GEO_QUEUE` 指向 `cf-vless-trojan-d1-geo-update`。若漏加生产者绑定，`env.GEO_QUEUE` 为 `undefined`，geo 更新消息无法入队，进度弹框会一直卡在「更新中… 进度 0/0」。注意：即使 Consumer 触发器与队列资源已存在，缺少生产者绑定仍无法投递消息。

### 6. 添加 Cron 触发器（推荐）

Worker 页面 → **Settings** → **Triggers** → **Cron Triggers** → **Add cron trigger**，表达式填 `0 3 * * *`（每日 03:00 自动更新 Geo 数据）。

### 7. （可选）绑定自定义域名

Worker 页面 → **Settings** → **Domains & Routes** → **Add custom domain**，输入你的域名完成绑定。

### 8. 开始使用

访问 `https://cf-vless-trojan-d1.<你的子域>.workers.dev/admin`，页面会显示首次部署初始密码，登录后台即可添加用户、配置分流规则。

## 首次使用

1. 访问 `https://<你的域名>/admin`，页面会显示**首次部署初始密码**（自动生成并落库，登录后请及时修改）。
2. 在后台添加 VLESS 用户（UUID）与 Trojan 用户（密码）。
3. 订阅地址：
   - 聚合订阅：`https://<域名>/subscribe?token=<admin密码>`
   - 单凭据页：`https://<域名>/uuid=<UUID>` 或 `https://<域名>/password=<密码>`
   - 客户端订阅需带 ws path（默认 `/`，可在后台系统设置修改）。
4. 后台可管理出站代理、分流规则、查看流量统计、运行网络状态检测，并手动触发 Geo 数据更新（弹窗实时显示逐分类进度）。

## 构建

```bash
npm run build        # build:plain（esbuild 产出 _worker明.js）+ build:obf（混淆产出 _worker.js）
npm run dev          # wrangler dev 本地调试
npm run deploy       # wrangler deploy 发布
```

## 环境变量说明

不依赖环境变量；所有配置（ws 路径、默认出站、proxyip、udp 出站代理、入口设置、admin 密码、伪装页标题等）均存于 D1 `settings` 表，可在后台系统设置中修改。运行时依赖四个绑定：D1（`DB`）、KV（`GEO_KV`）、Workers Queues（`GEO_QUEUE`，geo 更新队列）、Durable Objects（`PROXY_DO`，WS 长连接会话托管，class_name=`ProxySessionDO`），均已在 `wrangler.toml` 中声明（含 `[[migrations]] new_sqlite_classes`）；控制台手动部署时需手动添加 `GEO_QUEUE` 生产者绑定（见上文踩坑提示），并手动添加 `PROXY_DO` 的 Durable Object 绑定与 migration（见上文第 5 节）。若 `PROXY_DO` 缺失，WS 会话自动回退 Worker 内处理，功能可用但不具备长连接保活。
