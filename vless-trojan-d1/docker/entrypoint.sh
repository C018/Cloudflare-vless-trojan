#!/bin/sh
# vless-trojan-d1 Docker entrypoint
# 职责：
#   1) 首次启动时幂等初始化 D1（本地 SQLite 库不存在 settings 表则导入 schema.sql）
#   2) 用 wrangler dev 本地运行时启动 _worker.js（绑定 D1/KV/Queues 全部本地模拟）
#
# 注意：本文件必须使用 LF 换行符（勿用 CRLF），否则容器内 /bin/sh 会报错。

set -e

DATA_DIR="${DATA_DIR:-/data}"
SCHEMA_FILE="/app/schema.sql"
CONFIG_FILE="/app/wrangler.toml"
PORT="${PORT:-8787}"

# wrangler.toml 中的 D1/KV ID 是 REPLACE 占位符，本地模式可直接使用（已验证），无需修改配置。
# 幂等初始化：避免每次启动执行 wrangler d1 execute 查询（该命令在部分环境下会挂起卡死），
# 改用 marker 文件 + 持久化目录中 SQLite 文件存在性判断：
#   - 已存在 /data/.d1-initialized 标记，或
#   - 已存在 wrangler --persist-to 生成的 *.sqlite 数据库文件
# 均视为已初始化，跳过 schema 导入。
if [ -f "$DATA_DIR/.d1-initialized" ] || \
   find "$DATA_DIR" -name '*.sqlite*' -print -quit 2>/dev/null | grep -q .; then
  echo "[init] D1 already initialized, skip schema import"
else
  echo "[init] First run: importing schema.sql ..."
  mkdir -p "$DATA_DIR"
  npx wrangler d1 execute DB --local --persist-to="$DATA_DIR" --file="$SCHEMA_FILE"
  touch "$DATA_DIR/.d1-initialized"
  echo "[init] D1 schema imported"
fi

# 启动 worker（本地运行时监听 0.0.0.0:8787，供 Caddy 反向代理）
# 参数说明：
#   --config     使用项目自带 wrangler.toml（含 D1/KV/Queues/Cron 绑定，本地模式自动模拟）
#   --persist-to 持久化目录（D1 SQLite、KV 数据、Cache 均存于此）
#   --ip         监听地址（wrangler v4 中监听地址用 --ip，--host 已是转发目标）
#   --port       监听端口
echo "[init] Starting worker on 0.0.0.0:${PORT} ..."
exec npx wrangler dev --config "$CONFIG_FILE" \
  --persist-to="$DATA_DIR" \
  --ip 0.0.0.0 \
  --port "$PORT"
