#!/usr/bin/env bash
# 从 DDNS 中枢拉取通配符证书到本地目录，变化时替换并可选 reload 服务
# 用法（环境变量）：
#   CERT_KEY   必填，面板为该主域名生成的独立证书同步凭据
#   CERT_API   证书中枢地址，默认 https://ddns.227755.xyz
#   CERT_DIR   本地落地目录，默认 /etc/ssl/mycerts
#   RELOAD_CMD 变化后执行的命令，如 "nginx -s reload" 或 "systemctl reload nginx"
set -euo pipefail

KEY="${CERT_KEY:?请设置 CERT_KEY（独立证书同步凭据）}"
API="${CERT_API:-https://ddns.227755.xyz}"
DIR="${CERT_DIR:-/etc/ssl/mycerts}"
RELOAD="${RELOAD_CMD:-}"

mkdir -p "$DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 密钥只放在请求头，避免进入浏览器、CDN、反向代理和应用访问日志。
auth=(-H "Authorization: Bearer $KEY")
curl -4fsS --proto '=https' --tlsv1.2 "${auth[@]}" "$API/cert/fullchain" -o "$tmp/fullchain.pem"
curl -4fsS --proto '=https' --tlsv1.2 "${auth[@]}" "$API/cert/key"       -o "$tmp/key.pem"

# 基本校验，避免把错误页写进证书
grep -q "BEGIN CERTIFICATE"    "$tmp/fullchain.pem" || { echo "[cert] fullchain 无效，放弃"; exit 1; }
grep -q "BEGIN.*PRIVATE KEY"   "$tmp/key.pem"       || { echo "[cert] key 无效，放弃"; exit 1; }

changed=0
for f in fullchain.pem key.pem; do
  if ! cmp -s "$tmp/$f" "$DIR/$f" 2>/dev/null; then
    mode=600
    [ "$f" = fullchain.pem ] && mode=644
    install -m "$mode" "$tmp/$f" "$DIR/$f.new"
    mv -f "$DIR/$f.new" "$DIR/$f"
    changed=1
  fi
done
chmod 644 "$DIR/fullchain.pem"; chmod 600 "$DIR/key.pem"

if [ "$changed" = 1 ]; then
  echo "[cert] $(date '+%F %T') 证书已更新 -> $DIR"
  [ -n "$RELOAD" ] && { echo "[cert] running configured reload command"; /bin/sh -c "$RELOAD"; }
else
  echo "[cert] $(date '+%F %T') 证书无变化"
fi
