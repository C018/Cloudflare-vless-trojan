# syntax=docker/dockerfile:1
# vless-trojan-d1 Docker 镜像
# 思路：在容器内用 Cloudflare 官方本地运行时（wrangler dev，基于 miniflare/workerd）
# 直接运行 _worker.js（Module Worker 格式，不能裸 node 运行），
# D1/KV/Queues 全部映射到本地模拟，数据持久化在 /data volume。
#
# 构建方式（在项目根执行）：
#   docker build -f docker/Dockerfile -t vless-trojan-d1 .
# 或直接 docker compose -f docker/docker-compose.yml up -d --build

FROM node:22-slim

WORKDIR /app

# 先复制依赖清单以利用 Docker 层缓存
COPY package.json package-lock.json ./
# wrangler 是 devDependency，npm ci 默认安装 dev 依赖，保留即可
RUN npm ci --omit=optional

# 只复制运行所需的构建产物与配置（白名单复制，不依赖 .dockerignore 也能保证镜像干净）
COPY wrangler.toml ./
COPY _worker.js ./
COPY schema.sql ./
COPY docker/entrypoint.sh ./entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENV DATA_DIR=/data
ENV PORT=8787

EXPOSE 8787
VOLUME ["/data"]

ENTRYPOINT ["/app/entrypoint.sh"]
