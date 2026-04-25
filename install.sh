#!/bin/bash
set -e

# ============================================================
#  NginxFlow 一键安装脚本
#  用法: curl -sSL http://59.57.180.176:53000/anker/nginxflow/raw/branch/master/install.sh | bash
#  自定义端口: NGINXFLOW_PORT=8080 bash install.sh
# ============================================================

INSTALL_DIR="/opt/nginxflow"
DATA_DIR="$INSTALL_DIR/data"
SERVICE_NAME="nginxflow"
GITEA="http://59.57.180.176:53000"
REPO="anker/nginxflow"
PORT="${NGINXFLOW_PORT:-9000}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}▶ $*${NC}"; }

echo -e "${BLUE}"
echo "  ███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗  ██╗███████╗██╗      ██████╗ ██╗    ██╗"
echo "  ████╗  ██║██╔════╝ ██║████╗  ██║╚██╗██╔╝██╔════╝██║     ██╔═══██╗██║    ██║"
echo "  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║ ╚███╔╝ █████╗  ██║     ██║   ██║██║ █╗ ██║"
echo "  ██║╚██╗██║██║   ██║██║██║╚██╗██║ ██╔██╗ ██╔══╝  ██║     ██║   ██║██║███╗██║"
echo "  ██║ ╚████║╚██████╔╝██║██║ ╚████║██╔╝ ██╗██║     ███████╗╚██████╔╝╚███╔███╔╝"
echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ "
echo -e "${NC}"
echo "  Nginx 反向代理可视化管理系统  |  安装端口: $PORT"
echo "  ─────────────────────────────────────────────────────"

# ── 权限检查 ────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请以 root 或 sudo 运行此脚本"

# ── 系统检查 ────────────────────────────────────────────────
step "检查系统环境"
if ! command -v apt-get &>/dev/null; then
  error "目前仅支持 Debian/Ubuntu 系统"
fi
info "系统: $(lsb_release -ds 2>/dev/null || uname -sr)"

# ── 安装 nginx ──────────────────────────────────────────────
step "检查 Nginx"
if command -v nginx &>/dev/null; then
  info "Nginx 已安装: $(nginx -v 2>&1)"
else
  info "安装 Nginx..."
  apt-get update -qq
  apt-get install -y nginx
  info "Nginx 安装完成"
fi

# ── 下载二进制 ──────────────────────────────────────────────
step "下载最新版本"
LATEST_TAG=$(curl -sf "$GITEA/api/v1/repos/$REPO/releases/latest" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null) \
  || error "无法获取版本信息，请检查 $GITEA 是否可访问"

info "最新版本: $LATEST_TAG"
ASSET_URL="$GITEA/api/v1/repos/$REPO/releases/latest"
DL_URL=$(curl -sf "$ASSET_URL" \
  | python3 -c "import sys,json; assets=json.load(sys.stdin).get('assets',[]); print(next((a['browser_download_url'] for a in assets if a['name']=='nginxflow-server'),''))" 2>/dev/null)

[[ -z "$DL_URL" ]] && error "未找到可下载的二进制文件"

curl -sf --progress-bar -o /tmp/nginxflow-server "$DL_URL" || error "下载失败: $DL_URL"
chmod +x /tmp/nginxflow-server
info "下载完成"

# ── 停止旧服务 ──────────────────────────────────────────────
step "准备安装目录"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  warn "停止现有服务..."
  systemctl stop "$SERVICE_NAME"
fi
mkdir -p "$DATA_DIR"
cp /tmp/nginxflow-server "$INSTALL_DIR/nginxflow-server"
info "二进制已安装到 $INSTALL_DIR/nginxflow-server"

# ── 生成配置（首次安装才写）──────────────────────────────────
if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
  step "生成配置文件"
  JWT_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#^&*' | head -c 48)
  cat > "$INSTALL_DIR/config.yaml" << EOF
server:
  port: $PORT

nginx:
  conf_dir: /etc/nginx/conf.d
  reload_cmd: nginx -s reload
  test_cmd: nginx -t

db:
  path: $DATA_DIR/nginxflow.db

jwt:
  secret: "$JWT_SECRET"
EOF
  info "配置文件已生成"
else
  warn "config.yaml 已存在，跳过（保留原有配置）"
fi

# ── 配置 Nginx ──────────────────────────────────────────────
step "配置 Nginx"
cat > /etc/nginx/nginx.conf << 'NGINX_EOF'
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
    log_format nginxflow_http '$remote_addr - $remote_user [$time_local] "$request" '
                              '$status $body_bytes_sent "$http_referer" "$http_user_agent" $upstream_addr';

    include /etc/nginx/conf.d/*-http.conf;
}

stream {
    log_format basic '$remote_addr [$time_local] '
                     '$protocol $status $bytes_sent $bytes_received '
                     '$session_time "$upstream_addr"';
    include /etc/nginx/conf.d/*-stream.conf;
}
NGINX_EOF

nginx -t && nginx -s reload 2>/dev/null || nginx 2>/dev/null
info "Nginx 配置完成"

# ── 创建 systemd 服务 ────────────────────────────────────────
step "注册系统服务"
cat > /etc/systemd/system/nginxflow.service << EOF
[Unit]
Description=NginxFlow Server
After=network.target nginx.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/nginxflow-server -config $INSTALL_DIR/config.yaml
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=5
StandardOutput=append:/var/log/nginxflow/app.log
StandardError=append:/var/log/nginxflow/app.log

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/log/nginxflow
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
echo -e "${GREEN}║${NC}  访问地址: ${BLUE}http://$IP:$PORT${NC}"
echo -e "${GREEN}║${NC}  默认账号: ${YELLOW}admin${NC}"
echo -e "${GREEN}║${NC}  默认密码: ${YELLOW}admin123${NC}"
echo -e "${GREEN}║${NC}  配置文件: $INSTALL_DIR/config.yaml"
echo -e "${GREEN}║${NC}  数据目录: $DATA_DIR"
echo -e "${GREEN}║${NC}  服务日志: journalctl -u nginxflow -f"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
