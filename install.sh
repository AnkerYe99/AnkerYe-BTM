#!/bin/bash
set -e

# ============================================================
#  NginxFlow 一键安装脚本
#
#  公网（GitHub）:
#    curl -sSL https://raw.githubusercontent.com/AnkerYe99/nginxflow/master/install.sh | bash
#
#  内网（Gitea）:
#    GITEA_URL=http://10.14.6.51:3000 curl -sSL http://10.14.6.51:3000/anker/nginxflow/raw/branch/master/install.sh | bash
#
#  自定义端口:
#    NGINXFLOW_PORT=8080 bash install.sh
# ============================================================

GITEA_REPO="anker/nginxflow"
GITHUB_REPO="AnkerYe99/nginxflow"
INSTALL_DIR="/opt/nginxflow"
DATA_DIR="$INSTALL_DIR/data"
LOG_DIR="/var/log/nginxflow"
SERVICE_NAME="nginxflow"
PORT="${NGINXFLOW_PORT:-9000}"

# ── 颜色 ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}▶ $*${NC}"; }

echo -e "${BLUE}"
echo "    _         _              __  __     "
echo "   / \   _ __ | | _____ _ __ \ \ / ___  "
echo "  / _ \ | '_ \| |/ / _ \ '__|  \ V / _ \ "
echo " / ___ \| | | |   <  __/ |      | |  __/ "
echo "/_/   \_\_| |_|_|\_\___|_|      |_|\___| "
echo -e "${NC}"
echo "  AnkerYe-Nginx 反向代理可视化管理系统  |  安装端口: $PORT"
echo "  ─────────────────────────────────────────────────────"

# ── 权限检查 ────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请以 root 或 sudo 运行此脚本"

# ── 系统检查 ────────────────────────────────────────────────
step "检查系统环境"
command -v apt-get &>/dev/null || error "目前仅支持 Debian/Ubuntu 系统"
command -v curl    &>/dev/null || { apt-get update -qq; apt-get install -y curl; }
command -v python3 &>/dev/null || { apt-get update -qq; apt-get install -y python3; }
info "系统: $(lsb_release -ds 2>/dev/null || uname -sr)"

# ── 自动探测下载源 ────────────────────────────────────────────
# 优先顺序：
#   1. 用户通过 GITEA_URL 环境变量手动指定内网 Gitea
#   2. 自动检测 GitHub（公网兜底）
# 不写死任何 IP，内网用户通过 GITEA_URL 传入地址即可
step "探测下载源"

DL_TYPE=""   # gitea | github
DL_BASE=""   # Gitea 时有值，GitHub 时为空

_get_release_json() {
  if [[ "$DL_TYPE" == "gitea" ]]; then
    curl -sf --connect-timeout 8 "$DL_BASE/api/v1/repos/$GITEA_REPO/releases/latest"
  else
    curl -sf --connect-timeout 8 "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
  fi
}

_parse_tag()      { python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null; }
_parse_asset_url(){ python3 -c "
import sys, json
assets = json.load(sys.stdin).get('assets', [])
url = next((a['browser_download_url'] for a in assets if a['name'] == 'nginxflow-server'), '')
print(url)
" 2>/dev/null; }

# 1. 用户指定 Gitea
if [[ -n "${GITEA_URL:-}" ]]; then
  if curl -sf --connect-timeout 5 "$GITEA_URL/api/v1/repos/$GITEA_REPO" -o /dev/null 2>/dev/null; then
    DL_TYPE="gitea"
    DL_BASE="${GITEA_URL%/}"   # 去掉末尾斜杠
    info "内网 Gitea: $DL_BASE"
  else
    warn "GITEA_URL=$GITEA_URL 无法访问，尝试 GitHub..."
  fi
fi

# 2. GitHub 兜底
if [[ -z "$DL_TYPE" ]]; then
  if curl -sf --connect-timeout 8 "https://api.github.com/repos/$GITHUB_REPO/releases/latest" -o /dev/null 2>/dev/null; then
    DL_TYPE="github"
    info "公网 GitHub: github.com/$GITHUB_REPO"
  fi
fi

[[ -z "$DL_TYPE" ]] && error "无法连接任何下载源。
  内网用户请指定 Gitea 地址: GITEA_URL=http://IP:PORT bash install.sh"

# ── 获取版本并下载二进制 ─────────────────────────────────────
step "下载最新版本"

RELEASE_JSON=$(_get_release_json) || error "无法获取 Release 信息"
LATEST_TAG=$(echo "$RELEASE_JSON" | _parse_tag)
DL_URL=$(echo "$RELEASE_JSON" | _parse_asset_url)

[[ -z "$LATEST_TAG" ]] && error "无法解析版本号，请确认已在仓库中创建 Release"
[[ -z "$DL_URL" ]]     && error "Release 中未找到 nginxflow-server 二进制，请先上传构建产物"

info "最新版本: $LATEST_TAG"
info "下载地址: $DL_URL"

DL_TMP=$(mktemp /tmp/nginxflow-XXXXXX 2>/dev/null || echo "/root/nginxflow-server-dl")
curl -fL --progress-bar -o "$DL_TMP" "$DL_URL" || error "下载失败"
chmod +x "$DL_TMP"
info "下载完成"

# ── 安装 Nginx ──────────────────────────────────────────────
step "检查 Nginx"
if command -v nginx &>/dev/null; then
  info "Nginx 已安装: $(nginx -v 2>&1)"
else
  info "安装 Nginx..."
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
cp "$DL_TMP" "$INSTALL_DIR/nginxflow-server"
rm -f "$DL_TMP"
info "二进制已安装到 $INSTALL_DIR/nginxflow-server"

# ── 生成配置（首次安装才写，升级时保留原有配置）────────────────
if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
  step "生成配置文件"
  JWT_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#^&*' | head -c 48)
  cat > "$INSTALL_DIR/config.yaml" << CFEOF
server:
  port: $PORT
  jwt_secret: "$JWT_SECRET"

database:
  path: $DATA_DIR/nginxflow.db

nginx:
  conf_dir: /etc/nginx/conf.d
  reload_cmd: nginx -s reload
  test_cmd: nginx -t
CFEOF
  info "配置文件已生成"
else
  # 检测旧格式并自动迁移（db: → database:  /  jwt.secret → server.jwt_secret）
  if grep -q "^db:" "$INSTALL_DIR/config.yaml" 2>/dev/null; then
    warn "检测到旧版配置格式，自动迁移..."
    cp "$INSTALL_DIR/config.yaml" "$INSTALL_DIR/config.yaml.bak"

    OLD_DB=$(grep -A1 "^db:" "$INSTALL_DIR/config.yaml" | grep "path:" | awk '{print $2}')
    OLD_JWT=$(grep -A1 "^jwt:" "$INSTALL_DIR/config.yaml" | grep "secret:" | sed 's/.*secret: *//;s/"//g')
    OLD_PORT=$(grep -A1 "^server:" "$INSTALL_DIR/config.yaml" | grep "port:" | awk '{print $2}')
    OLD_CONF=$(grep "conf_dir:" "$INSTALL_DIR/config.yaml" | awk '{print $2}')

    [[ -z "$OLD_PORT" ]] && OLD_PORT=$PORT
    [[ -z "$OLD_DB"   ]] && OLD_DB="$DATA_DIR/nginxflow.db"
    [[ -z "$OLD_CONF" ]] && OLD_CONF="/etc/nginx/conf.d"

    cat > "$INSTALL_DIR/config.yaml" << CFEOF
server:
  port: $OLD_PORT
  jwt_secret: "$OLD_JWT"

database:
  path: $OLD_DB

nginx:
  conf_dir: $OLD_CONF
  reload_cmd: nginx -s reload
  test_cmd: nginx -t
CFEOF
    info "配置迁移完成（旧配置备份于 config.yaml.bak）"
  else
    warn "config.yaml 已存在，保留原有配置（升级模式）"
  fi
fi

# ── 配置 Nginx ──────────────────────────────────────────────
step "配置 Nginx"
if [[ ! -f /etc/nginx/nginx.conf.nginxflow-bak ]]; then
  cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.nginxflow-bak
fi
cat > /etc/nginx/nginx.conf << 'NGINXEOF'
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

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
    log_format nginxflow '$remote_addr - $remote_user [$time_local] "$request" '
                         '$status $body_bytes_sent "$http_referer" "$http_user_agent" $upstream_addr';
    include /etc/nginx/conf.d/*-http.conf;
}

stream {
    log_format basic '$remote_addr [$time_local] $protocol $status '
                     '$bytes_sent $bytes_received $session_time "$upstream_addr"';
    include /etc/nginx/conf.d/*-stream.conf;
}
NGINXEOF

nginx -t 2>/dev/null && {
  if pgrep -x nginx &>/dev/null; then nginx -s reload; else nginx; fi
}
info "Nginx 配置完成"

# ── 注册系统服务 ─────────────────────────────────────────────
step "注册系统服务"
cat > /etc/systemd/system/nginxflow.service << SVCEOF
[Unit]
Description=NginxFlow Server
After=network.target nginx.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/nginxflow-server -config $INSTALL_DIR/config.yaml
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=5
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
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           NginxFlow 安装完成！                   ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  版本:     ${BLUE}$LATEST_TAG${NC}"
echo -e "${GREEN}║${NC}  访问地址: ${BLUE}http://$IP:$PORT${NC}"
echo -e "${GREEN}║${NC}  默认账号: ${YELLOW}admin${NC}"
echo -e "${GREEN}║${NC}  默认密码: ${YELLOW}admin123${NC}"
echo -e "${GREEN}║${NC}  配置文件: $INSTALL_DIR/config.yaml"
echo -e "${GREEN}║${NC}  数据目录: $DATA_DIR"
echo -e "${GREEN}║${NC}  运行日志: $LOG_DIR/app.log"
echo -e "${GREEN}║${NC}  服务管理: systemctl [start|stop|restart|status] $SERVICE_NAME"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
