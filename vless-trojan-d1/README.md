# vless-trojan-d1

基于 Cloudflare Workers + D1 + KV 的 VLESS / Trojan 双协议代理面板，单文件部署（`_worker.js` 混淆版 / `_worker明.js` 明码版）。

## 功能特性

- VLESS / Trojan 双入站，多 UUID / 多密码，独立启停
- 分流引擎：`geosite:` / `geoip:` / `domain:` / `full:` / `keyword:` / `ip-cidr:` / `regexp:`，规则排序匹配
- 出站：direct / socks5 / http / vless（vless 支持完整 UDP），规则未命中走默认出站
- Geo 数据：GEO_KV 存分类 JSON，Cron 每日 03:00 自动更新（HTTP 可手动触发），内置冷启动兜底
- 订阅生成：单节点 / 聚合（纯文本 / Base64 / Clash / sing-box），支持优选 IP 变体
- 单凭据配置页：`/uuid=<uuid>` 与 `/password=<密码>` 返回专属节点链接
- 后台：iOS 风格管理面板（流量统计、入站 / 出站 / 规则 / 设置管理），PBKDF2 + HMAC Cookie 鉴权
- 伪装页：内嵌静态仿 Alist 文件列表页，无外部依赖
- 流量统计：连接关闭后异步写 D1，按 UUID / 密码维度计数

## 目录结构

```
vless-trojan-d1/
├── src/
│   ├── index.js            # 入口路由（admin / cron / ws / 订阅 / 伪装页）
│   ├── cron.js             # 定时更新 Geo 数据
│   ├── config/
│   │   ├── constants.js    # 协议 / 出站 / geo / 优选域名常量
│   │   └── defaults.js     # D1 读取层 + 请求级配置缓存 + 初始密码生成
│   ├── protocol/
│   │   ├── vless.js        # VLESS 入站头解析 / 出站头构造
│   │   └── trojan.js       # Trojan 入站头解析（SHA224 密码比对）
│   ├── outbound/
│   │   ├── stream.js       # WebSocket 流工具
│   │   ├── socks5.js       # SOCKS5 出站
│   │   ├── http.js         # HTTP CONNECT 出站
│   │   ├── vless.js        # VLESS 出站（ws 隧道，TCP/UDP）
│   │   ├── udp.js          # UDP 帧拆组
│   │   └── tcp.js          # TCP 出站调度
│   ├── routing/
│   │   ├── geo.js          # Geo 数据加载（KV + 缓存 + 兜底）
│   │   └── engine.js       # 分流规则解析与匹配
│   ├── admin/
│   │   ├── auth.js         # PBKDF2 密码哈希 + HMAC 会话
│   │   ├── api.js          # REST API（登录 / CRUD / 统计 / geo 更新）
│   │   └── ui.js           # 后台单页 UI
│   ├── generators/
│   │   ├── subscription.js # 节点链接 / 订阅生成
│   │   └── config-page.js  # 单凭据配置页
│   └── disguise/
│       └── alist.js        # Alist 风格伪装页
├── schema.sql              # D1 建表与种子数据
├── wrangler.toml           # Worker / D1 / KV / Cron 绑定
├── package.json            # 构建链（esbuild + javascript-obfuscator）
├── _worker.js              # 混淆版部署产物
└── _worker明.js            # 明码版部署产物
```

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

### 3. 部署

```bash
npm install
npm run build        # 生成 _worker.js（混淆）与 _worker明.js（明码）
wrangler deploy
```

部署后可删除 `_worker明.js` 仅保留混淆版，降低被逆向概率。

## 单文件手动部署（控制台操作，免本地环境）

不依赖 Node.js / npm / wrangler CLI，全程在 Cloudflare 控制台完成。以下操作与 `wrangler deploy` 等效，绑定变量名与 `wrangler.toml` 保持一致（D1 绑定名 `DB`、KV 绑定名 `GEO_KV`）。

### 1. 创建 D1 数据库并建表

1. 打开 Cloudflare Dashboard → **Workers & Pages** → **D1** → **Create database**，命名为 `cf-vless-trojan-d1`。
2. 进入刚创建的数据库 → **Console**，将仓库内 `schema.sql` 的完整内容粘贴进去执行（建表与种子数据一次性完成）。

### 2. 创建 KV 命名空间

**Workers & Pages** → **KV** → **Create a namespace**，命名为 `GEO_KV`。

### 3. 创建 Worker 并粘贴代码

1. **Workers & Pages** → **Create application** → **Worker**，命名为 `cf-vless-trojan-d1`。
2. 用编辑器打开本地 `_worker.js`（混淆版部署产物），**全选复制全部内容**，在 Worker 编辑器中覆盖默认模板代码。
3. 点击 **Deploy** 完成首次部署。

### 4. 绑定 D1 与 KV

1. Worker 页面 → **Settings** → **Bindings** → **Add binding**：
   - **D1 database**：Variable name 填 `DB`，数据库选择 `cf-vless-trojan-d1`；
   - **KV namespace**：Variable name 填 `GEO_KV`，命名空间选择 `GEO_KV`。
2. 保存绑定后再次点击 **Deploy**，使绑定生效。

### 5. 添加 Cron 触发器（推荐）

Worker 页面 → **Settings** → **Triggers** → **Cron Triggers** → **Add cron trigger**，表达式填 `0 3 * * *`（每日 03:00 自动更新 Geo 数据）。

### 6. （可选）绑定自定义域名

Worker 页面 → **Settings** → **Domains & Routes** → **Add custom domain**，输入你的域名完成绑定。

### 7. 开始使用

访问 `https://cf-vless-trojan-d1.<你的子域>.workers.dev/admin`，页面会显示首次部署初始密码，登录后台即可添加用户、配置分流规则。

## 首次使用

1. 访问 `https://<你的域名>/admin`，页面会显示**首次部署初始密码**（自动生成并落库，登录后请及时修改）。
2. 在后台添加 VLESS 用户（UUID）与 Trojan 用户（密码）。
3. 订阅地址：
   - 聚合订阅：`https://<域名>/subscribe?token=<admin密码>`
   - 单凭据页：`https://<域名>/uuid=<UUID>` 或 `https://<域名>/password=<密码>`
   - 客户端订阅需带 ws path（默认 `/`，可在后台系统设置修改）。
4. 后台可管理出站代理、分流规则、查看流量统计，并手动触发 Geo 数据更新。

## 构建

```bash
npm run build        # build:plain（esbuild 产出 _worker明.js）+ build:obf（混淆产出 _worker.js）
npm run dev          # wrangler dev 本地调试
npm run deploy       # wrangler deploy 发布
```

## 环境变量说明

不依赖环境变量；所有配置（ws 路径、默认出站、admin 密码、优选 IP 列表 ip1-ip13/pt1-pt13、伪装页标题等）均存于 D1 `settings` 表，可在后台系统设置中修改。
