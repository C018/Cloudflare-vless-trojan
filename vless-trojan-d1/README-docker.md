---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 2b01018e553984e9a5671567693ea87d_29b654b4c6ba11f197b3525400248c00
    ReservedCode1: 3jFDHtwqJwTvWylS9j8wOhmr5sgQFfBz6j0+uurSZL4Zd/DdVX9p7L9PPsxdM6sy6HIlQb482gbt7+eeWdogAnRDLdqni3Rb84QdSwIxJ4Jx+lmtgtMebkCbSLK3oVfaOao4J0/6R5HcNp4lRcqQhDOrVxuEstjS+s8jCdVU9PcuX2hCduaawYyMHt0=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 2b01018e553984e9a5671567693ea87d_29b654b4c6ba11f197b3525400248c00
    ReservedCode2: 3jFDHtwqJwTvWylS9j8wOhmr5sgQFfBz6j0+uurSZL4Zd/DdVX9p7L9PPsxdM6sy6HIlQb482gbt7+eeWdogAnRDLdqni3Rb84QdSwIxJ4Jx+lmtgtMebkCbSLK3oVfaOao4J0/6R5HcNp4lRcqQhDOrVxuEstjS+s8jCdVU9PcuX2hCduaawYyMHt0=
---

# vless-trojan-d1 Docker 部署指南

在 VPS 上用 Docker 部署 vless-trojan-d1 管理后台（VLESS / Trojan 双协议），并支持 SSL 证书。

> 本项目本体是 Cloudflare Workers 项目（单文件 `_worker.js`），常规部署需上传到 Cloudflare。
> 本指南提供**完全本地化**的 Docker 部署方案：容器内使用 Cloudflare 官方本地运行时
> （`wrangler dev`，基于 miniflare / workerd）直接运行 `_worker.js`，
> 所有绑定（D1 / KV / Queues / Cron）均映射到本地模拟，数据落在 Docker volume 中。

---

## 1. 架构说明

```
                        公网用户
                           │ 443/80 (HTTPS)
                           ▼
   ┌─────────────┐   ┌───────────────────┐
   │ caddy:2-alpine│──▶│  worker (node:20) │
   │ 反向代理 + 自动│   │  wrangler dev      │
   │ 申请/续期证书 │   │  本地运行时         │
   └─────────────┘   │  监听 0.0.0.0:8787  │
                     └─────────┬───────────┘
                               │ /data (volume)
   ┌─────────────┐             ▼
   │ cron (alpine)│──每日03:00──▶ D1 SQLite / KV / Cache
   │ 触发 scheduled│  触发 /cdn-cgi/local/scheduled
   └─────────────┘
```

| 服务 | 镜像 | 作用 |
|---|---|---|
| `worker` | 本项目构建（node:20-slim） | 运行 `_worker.js` 的本地运行时，D1/KV/Queues 全本地模拟，数据持久化在 `/data` |
| `caddy` | caddy:2-alpine | 反向代理到 `worker:8787`，自动申请/续期 Let's Encrypt 证书 |
| `cron` | alpine:3 | 本地模式 Cron 不会自动触发，此容器每日 03:00 手动触发 scheduled 事件（geo 数据更新） |

### 关键文件

```
docker/
├── Dockerfile          # worker 镜像（npm ci + 复用构建产物 _worker.js）
├── docker-compose.yml  # 三服务编排
├── Caddyfile           # 反向代理 + 自动 HTTPS（含已有证书/纯 HTTP 注释示例）
├── entrypoint.sh       # 首次启动幂等初始化 D1 + 启动 wrangler dev
├── .dockerignore       # 构建忽略模板（复制到项目根生效）
└── .env.example        # 环境变量样例
README-docker.md        # 本文件
```

---

## 2. 一键启动

前置条件：VPS 已安装 Docker Engine + Docker Compose（`docker compose` 插件或 `docker-compose`）。

```bash
# 进入 docker 目录
cd docker

# 1. 准备环境变量（修改 DOMAIN 为你的正式域名）
cp .env.example .env
# vi .env

# 2. 构建并启动（首次会自动 npm ci 安装 wrangler，稍慢）
docker compose up -d --build

# 3. 查看状态
docker compose ps
docker compose logs -f worker   # 首次启动会看到 [init] D1 schema imported
docker compose logs -f caddy
```

启动完成后：
- 后台地址：`https://你的域名/admin`
- worker 直连调试地址（仅本机）：`http://127.0.0.1:8787/admin`
- 默认用户种子：VLESS `86c50e3a-5b87-49dd-bd20-03c7f2735e40`（default）、Trojan `trojan`（default），登录后请在后台修改

停止：`docker compose down`（保留 volume 数据）；彻底清理（含数据）：`docker compose down -v`。

---

## 3. 数据持久化与备份

所有运行数据都在名为 `worker-data` 的 Docker volume（挂载到容器 `/data`）中：

```
/data
└── v3/
    ├── d1/     # D1 SQLite 数据库（miniflare-D1DatabaseObject/<hash>/metadata.sqlite）
    ├── kv/     # KV 数据（geo 更新等）
    └── cache/  # Cache 对象
```

备份：

```bash
# 方式一：tar 打包 volume（推荐，worker 停止时执行更安全）
docker run --rm -v worker-data:/data -v "$PWD":/backup alpine tar czf /backup/vless-trojan-d1-backup-$(date +%F).tar.gz -C /data .

# 方式二：用 wrangler 导出 SQL（需在 docker 目录内临时起容器执行，见常见问题 4）
```

恢复：解压备份后 `docker run --rm -v worker-data:/data -v "$PWD":/backup alpine tar xzf /backup/xxx.tar.gz -C /data`，再重启 `docker compose up -d`。

> 注意：D1 首次初始化是**幂等**的（schema.sql 全部 `IF NOT EXISTS` + `INSERT OR IGNORE`），
> 即使误删库后重启也会自动重建表和种子数据，不会重复插入。

---

## 4. SSL 三种模式

### 模式一：正式域名 + 自动 HTTPS（默认，推荐）

`.env` 中设置 `DOMAIN` 与 `ACME_EMAIL`，Caddy 自动向 Let's Encrypt 申请并续期证书。

前提：
- `DOMAIN` 的 A/AAAA 记录已解析到本机公网 IP
- 服务器防火墙放行 80（ACME HTTP-01 验证）与 443 端口

Caddy 会在 `caddy-data` volume 中缓存证书，续期自动完成，无需干预。

### 模式二：挂载已有证书

将证书文件放入 `docker/certs/` 目录（`fullchain.pem` + `privkey.pem`），
按 `docker/Caddyfile` 中"模式二"注释示例修改（`tls /etc/caddy/certs/...`）后重启：

```bash
mkdir -p certs
# 将 fullchain.pem / privkey.pem 放入 certs/
vi Caddyfile   # 启用模式二块，注释模式一块
docker compose up -d --force-recreate caddy
```

### 模式三：内部/无证书（纯 HTTP）

不需要域名和证书：`.env` 中 `DOMAIN` 留空，按 `docker/Caddyfile` 中"模式三"注释示例
将 `:80` 块启用、注释掉 `{$DOMAIN}` 块，然后 `docker compose up -d --force-recreate caddy`。

> 不建议在公网直接使用纯 HTTP 模式（流量不加密），仅适合内网调试。

---

## 5. 常见问题

1. **wrangler.toml 里 D1/KV 的 ID 是 `REPLACE_WITH_YOUR_...` 占位符，本地部署要不要改？**
   不需要。本地模式（`--local`）下 wrangler 接受任意字符串作为本地 ID，占位符可直接使用，
   绑定（DB / GEO_KV / GEO_QUEUE）会正常映射到本地模拟。已实测验证。

2. **Cron 定时任务会执行吗？**
   本地模式下 **Cron 不会自动触发**（wrangler 官方行为，会打印提示）。本方案用 `cron` sidecar
   容器每日 03:00 手动请求 `http://worker:8787/cdn-cgi/local/scheduled` 触发 scheduled 事件。
   也可在后台手动触发 geo 更新（管理面板相关按钮走 Queues，本地模拟同样可用）。

3. **为什么 worker 端口只绑定了 127.0.0.1？**
   公网入口只有 Caddy（443/80），避免未加密流量直连 worker。需要外部调试时改为 `8787:8787` 或加防火墙规则。

4. **如何手动重跑 D1 初始化 / 导入 schema？**
   ```bash
   docker compose exec worker npx wrangler d1 execute DB --local --persist-to=/data --file=/app/schema.sql
   ```
   由于 schema 幂等，重复执行安全。

5. **Windows 用户注意**
   `entrypoint.sh` 必须为 LF 换行符（仓库内已保证；若用记事本编辑过，用 `sed -i 's/\r$//' entrypoint.sh`
   或 Git 检出时启用 autocrlf 处理）。`.env.example` 复制为 `.env` 时注意编码为 UTF-8。

6. **构建/启动较慢？**
   首次 `npm ci` 会安装全部依赖（含 wrangler），之后镜像层缓存生效。`docker compose build --no-cache` 可强制重建。

7. **compatibility_date / placement / observability 在本地是否生效？**
   `placement` 与 `observability` 本地模式会忽略；`compatibility_date` 生效（wrangler 4.142.0 已验证可解析）。

---

## 6. 已验证 / 待验证

以下验证在 Windows 11 本机（Node v24.19.0 / npm 11.17.0 / wrangler 4.142.0，无 Docker）完成：

| 项目 | 结果 |
|---|---|
| `npm ci` 安装项目依赖（wrangler 4.142.0） | ✅ 成功 |
| `wrangler d1 execute DB --local --persist-to=... --file=schema.sql`（占位符 ID） | ✅ 成功，8 条命令执行 |
| `wrangler dev --local --persist-to=... --ip 0.0.0.0 --port 8787 --config wrangler.toml` | ✅ 成功，D1/KV/Queues 绑定全部本地解析 |
| 访问 `/admin` | ✅ HTTP 200（Worker 正常服务） |
| 持久化目录结构（v3/d1、v3/kv、v3/cache） | ✅ 确认 |
| 本地模式 Cron 不自动触发 | ✅ 确认（方案已用 cron sidecar 解决） |

待验证（本机无 Docker / 无公网域名，未实测）：

| 项目 | 说明 |
|---|---|
| Docker 镜像构建与三容器编排 | 需在有 Docker 的 VPS 上验证 |
| Let's Encrypt 自动签发/续期 | 需公网域名解析 + 80/443 开放 |
| cron sidecar 定时触发 scheduled 后 geo 更新 | 取决于容器时区（默认 UTC，03:00 即 UTC 时间）与网络 |
| 已有证书挂载（模式二） | 按 Caddyfile 注释操作即可，未实测 |

如遇问题请以 `docker compose logs` 输出为准排查。
*（内容由AI生成，仅供参考）*
