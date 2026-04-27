#!/bin/bash
set -e

# ============================================================
#  AnkerYe - 流量管理 (AnkerYe-BTM) 一键安装脚本
#
#  GitHub（公网）:
#    curl -sSL https://raw.githubusercontent.com/AnkerYe99/AnkerYe-BTM/master/install.sh | bash
#
#  内网 Gitea:
#    GITEA_URL=http://10.14.6.51:3000 bash <(curl -sSL http://10.14.6.51:3000/anker/AnkerYe-BTM/raw/branch/master/install.sh)
#
#  自定义端口:
#    BTM_PORT=8080 bash install.sh
# ============================================================

GITEA_REPO="anker/AnkerYe-BTM"
GITHUB_REPO="AnkerYe99/AnkerYe-BTM"
INSTALL_DIR="/opt/AnkerYe-BTM"
DATA_DIR="$INSTALL_DIR/data"
LOG_DIR="/var/log/AnkerYe-BTM"
SERVICE_NAME="AnkerYe-BTM"
BIN_NAME="ankerye-flow-server"
PORT="${BTM_PORT:-9000}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}▶ $*${NC}"; }

echo -e "${BLUE}"
cat << 'BANNER'
    _         _              __   __
   / \   _ __ | | _____ _ __ \ \ / ___
  / _ \ | '_ \| |/ / _ \ '__|  \ V / _ \
 / ___ \| | | |   <  __/ |      | |  __/
/_/   \_\_| |_|_|\_\___|_|      |_|\___|
BANNER
echo -e "${NC}"
echo "  AnkerYe-BTM 反向代理流量管理系统  |  安装端口: $PORT"
echo "  ─────────────────────────────────────────────────────"

# ── 权限检查 ────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请以 root 或 sudo 运行此脚本"

# ── 系统检查 ────────────────────────────────────────────────
step "检查系统环境"
command -v apt-get &>/dev/null || error "目前仅支持 Debian/Ubuntu 系统"
for pkg in curl python3; do
  command -v $pkg &>/dev/null || { apt-get update -qq; apt-get install -y $pkg; }
done
info "系统: $(lsb_release -ds 2>/dev/null || uname -sr)"

# ── 探测下载源 ────────────────────────────────────────────
step "探测下载源"
DL_TYPE=""
DL_BASE=""

_get_release_json() {
  if [[ "$DL_TYPE" == "gitea" ]]; then
    curl -sf --connect-timeout 8 "$DL_BASE/api/v1/repos/$GITEA_REPO/releases/latest"
  else
    curl -sf --connect-timeout 8 "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
  fi
}

_parse_tag() {
  python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null
}

_parse_asset_url() {
  python3 -c "
import sys, json
assets = json.load(sys.stdin).get('assets', [])
url = next((a['browser_download_url'] for a in assets if a['name'] == '$BIN_NAME'), '')
print(url)
" 2>/dev/null
}

if [[ -n "${GITEA_URL:-}" ]]; then
  if curl -sf --connect-timeout 5 "$GITEA_URL/api/v1/repos/$GITEA_REPO" -o /dev/null 2>/dev/null; then
    DL_TYPE="gitea"
    DL_BASE="${GITEA_URL%/}"
    info "内网 Gitea: $DL_BASE"
  else
    warn "GITEA_URL=$GITEA_URL 无法访问，尝试 GitHub..."
  fi
fi

if [[ -z "$DL_TYPE" ]]; then
  if curl -sf --connect-timeout 8 "https://api.github.com/repos/$GITHUB_REPO/releases/latest" -o /dev/null 2>/dev/null; then
    DL_TYPE="github"
    info "公网 GitHub: github.com/$GITHUB_REPO"
  fi
fi

[[ -z "$DL_TYPE" ]] && error "无法连接任何下载源。内网用户请指定: GITEA_URL=http://IP:PORT bash install.sh"

# ── 下载二进制 ─────────────────────────────────────────────
step "下载最新版本"
RELEASE_JSON=$(_get_release_json) || error "无法获取 Release 信息"
LATEST_TAG=$(echo "$RELEASE_JSON" | _parse_tag)
DL_URL=$(echo "$RELEASE_JSON" | _parse_asset_url)

[[ -z "$LATEST_TAG" ]] && error "无法解析版本号，请确认已在仓库中创建 Release"
[[ -z "$DL_URL" ]]     && error "Release 中未找到 $BIN_NAME 二进制，请先上传构建产物"

info "最新版本: $LATEST_TAG"
info "下载地址: $DL_URL"

DL_TMP=$(mktemp /tmp/ankerye-btm-XXXXXX)
curl -fL --progress-bar -o "$DL_TMP" "$DL_URL" || error "下载失败"
chmod +x "$DL_TMP"
info "下载完成"

# ── 安装 Nginx ──────────────────────────────────────────────
step "检查 Nginx"
if command -v nginx &>/dev/null; then
  info "Nginx 已安装: $(nginx -v 2>&1)"
else
  apt-get update -qq
  apt-get install -y nginx
  info "Nginx 安装完成"
fi

# ── 停止旧服务 ──────────────────────────────────────────────
step "准备安装目录"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  warn "停止现有服务..."
  systemctl stop "$SERVICE_NAME"
fi
mkdir -p "$DATA_DIR" "$LOG_DIR"
cp "$DL_TMP" "$INSTALL_DIR/$BIN_NAME"
rm -f "$DL_TMP"
chmod +x "$INSTALL_DIR/$BIN_NAME"
info "二进制已安装到 $INSTALL_DIR/$BIN_NAME"

# ── 生成配置 ────────────────────────────────────────────────
if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
  step "生成配置文件"
  JWT_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#^&*' | head -c 48)
  cat > "$INSTALL_DIR/config.yaml" << CFEOF
server:
  port: $PORT
  jwt_secret: "$JWT_SECRET"
  jwt_expire_hours: 24

database:
  path: $DATA_DIR/ankerye-btm.db

nginx:
  conf_dir: /etc/nginx/conf.d
  cert_dir: /etc/nginx/certs
  log_dir: $LOG_DIR
  logrotate_dir: /etc/logrotate.d
  reload_cmd: nginx -s reload
  test_cmd: nginx -t

health_check:
  default_interval: 10
  default_timeout: 3

cert:
  renew_before_days: 10
  check_hour: 2
CFEOF
  info "配置文件已生成"
else
  warn "config.yaml 已存在，保留原有配置（升级模式）"
fi

# ── 配置 Nginx ──────────────────────────────────────────────
step "配置 Nginx"
[[ ! -f /etc/nginx/nginx.conf.btm-bak ]] && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.btm-bak

# 检测是否有 stream 模块
STREAM_MOD=""
for f in /usr/lib/nginx/modules/ngx_stream_module.so /usr/share/nginx/modules/ngx_stream_module.so; do
  [[ -f "$f" ]] && STREAM_MOD="load_module $f;" && break
done

cat > /etc/nginx/nginx.conf << NGINXEOF
${STREAM_MOD}

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    client_max_body_size 64m;
    log_format ankerye_btm '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                            '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent" \$upstream_addr';
    include /etc/nginx/conf.d/*-http.conf;
}
NGINXEOF

if [[ -n "$STREAM_MOD" ]]; then
  cat >> /etc/nginx/nginx.conf << 'NGINXEOF'

stream {
    log_format basic '$remote_addr [$time_local] $protocol $status '
                     '$bytes_sent $bytes_received $session_time "$upstream_addr"';
    include /etc/nginx/conf.d/*-stream.conf;
}
NGINXEOF
fi

mkdir -p /etc/nginx/certs
nginx -t 2>/dev/null && {
  if pgrep -x nginx &>/dev/null; then nginx -s reload; else nginx; fi
}
info "Nginx 配置完成"

# ── 注册 systemd 服务 ────────────────────────────────────────
step "注册系统服务"
cat > /etc/systemd/system/$SERVICE_NAME.service << SVCEOF
[Unit]
Description=AnkerYe - 流量管理
After=network.target nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BIN_NAME -config $INSTALL_DIR/config.yaml
Restart=on-failure
RestartSec=5
Environment=TZ=Asia/Shanghai
StandardOutput=append:$LOG_DIR/app.log
StandardError=append:$LOG_DIR/app.log

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
  info "服务启动成功"
else
  error "服务启动失败，请查看: journalctl -u $SERVICE_NAME -n 30"
fi

# ── 完成 ────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        AnkerYe-BTM 安装完成！                        ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
printf "${GREEN}║${NC}  版本:     ${BLUE}%-38s${GREEN}║${NC}\n" "$LATEST_TAG"
printf "${GREEN}║${NC}  访问地址: ${BLUE}%-38s${GREEN}║${NC}\n" "http://$IP:$PORT"
printf "${GREEN}║${NC}  默认账号: ${YELLOW}%-38s${GREEN}║${NC}\n" "admin"
printf "${GREEN}║${NC}  默认密码: ${YELLOW}%-38s${GREEN}║${NC}\n" "admin123"
printf "${GREEN}║${NC}  配置文件: %-38s${GREEN}║${NC}\n" "$INSTALL_DIR/config.yaml"
printf "${GREEN}║${NC}  数据目录: %-38s${GREEN}║${NC}\n" "$DATA_DIR"
printf "${GREEN}║${NC}  运行日志: %-38s${GREEN}║${NC}\n" "$LOG_DIR/app.log"
echo -e "${GREEN}║${NC}  服务管理: systemctl [start|stop|restart|status] $SERVICE_NAME"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
