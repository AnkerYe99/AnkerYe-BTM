#!/bin/bash
# NginxFlow 一键安装脚本
# 支持 Ubuntu 20.04 / 22.04 / 24.04
set -e

# ─── 颜色 ────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

# ─── 配置 ────────────────────────────────────────────────
REPO="https://github.com/AnkerYe99/nginxflow.git"
INSTALL_DIR="/opt/nginxflow"
TMP_DIR="/tmp/nginxflow_install_$$"
GO_MIN_VERSION="1.21"
NODE_MIN_VERSION="18"
DEFAULT_PORT="9000"

# ─── 权限检查 ─────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || err "请使用 root 或 sudo 运行本脚本"

# ─── 端口配置（支持环境变量覆盖，默认 9000）─────────────────
APP_PORT=${APP_PORT:-$DEFAULT_PORT}
JWT_SECRET=$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 48 2>/dev/null)

# ─── 欢迎语 ──────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔═══════════════════════════════════════╗"
echo "║        NginxFlow  安装程序            ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"
info "管理后台端口: ${BOLD}$APP_PORT${NC}  （自定义端口: APP_PORT=8080 bash install.sh）"
echo ""

# ─── 检测包管理器 ─────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    err "不支持的系统，目前仅支持 apt / yum 系发行版"
fi

pkg_install() {
    if [ "$PKG_MGR" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"
    else
        yum install -y "$@"
    fi
}

# ─── 安装基础工具 ─────────────────────────────────────────
step "安装基础工具"
if [ "$PKG_MGR" = "apt" ]; then
    apt-get update -q
fi
pkg_install curl wget git unzip ca-certificates gnupg 2>/dev/null || true
ok "基础工具就绪"

# ─── 安装 Go ─────────────────────────────────────────────
step "检查 Go 环境"
need_go=true
if command -v go &>/dev/null; then
    cur=$(go version | grep -oP '\d+\.\d+' | head -1)
    maj=$(echo "$cur" | cut -d. -f1); min=$(echo "$cur" | cut -d. -f2)
    need_min=$(echo "$GO_MIN_VERSION" | cut -d. -f2)
    if [ "$maj" -ge 1 ] && [ "$min" -ge "$need_min" ]; then
        ok "Go $cur 已安装，跳过"
        need_go=false
    else
        warn "Go $cur 版本过低，将升级"
    fi
fi

if $need_go; then
    info "下载 Go 最新稳定版..."
    GO_VER=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    ARCH=$(uname -m); [ "$ARCH" = "x86_64" ] && ARCH="amd64" || ARCH="arm64"
    GO_PKG="${GO_VER}.linux-${ARCH}.tar.gz"
    wget -q --show-progress -O /tmp/go.tar.gz "https://go.dev/dl/${GO_PKG}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    chmod +x /etc/profile.d/go.sh
    export PATH=$PATH:/usr/local/go/bin
    ok "Go $(go version | awk '{print $3}') 安装完成"
fi
export PATH=$PATH:/usr/local/go/bin

# ─── 安装 Node.js ─────────────────────────────────────────
step "检查 Node.js 环境"
need_node=true
if command -v node &>/dev/null; then
    cur=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
    if [ "$cur" -ge "$NODE_MIN_VERSION" ]; then
        ok "Node.js v$(node -v | tr -d v) 已安装，跳过"
        need_node=false
    else
        warn "Node.js v$(node -v) 版本过低，将升级"
    fi
fi

if $need_node; then
    info "安装 Node.js 20 LTS..."
    if [ "$PKG_MGR" = "apt" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
        apt-get install -y -q nodejs
    else
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
        yum install -y nodejs
    fi
    ok "Node.js $(node -v) 安装完成"
fi

# ─── 安装 Nginx（含 stream 模块）────────────────────────────
step "检查 Nginx 环境"
if ! command -v nginx &>/dev/null; then
    info "安装 nginx..."
    pkg_install nginx
    ok "nginx 安装完成"
else
    ok "nginx $(nginx -v 2>&1 | grep -oP '[\d.]+') 已安装"
fi

if nginx -V 2>&1 | grep -q 'with-stream'; then
    ok "nginx stream 模块已内置"
elif [ -f /usr/lib/nginx/modules/ngx_stream_module.so ]; then
    ok "nginx stream 模块（动态）已存在"
else
    info "安装 nginx stream 模块..."
    pkg_install libnginx-mod-stream 2>/dev/null || \
    warn "无法自动安装 stream 模块，请手动安装 libnginx-mod-stream"
fi

# ─── 克隆源码 ────────────────────────────────────────────
step "获取源码"
rm -rf "$TMP_DIR"
info "克隆仓库..."
git clone --depth=1 "$REPO" "$TMP_DIR" 2>&1 | tail -1
ok "源码获取完成"

# ─── 编译前端 ────────────────────────────────────────────
step "编译前端"
cd "$TMP_DIR/frontend"
info "npm install..."
npm install --silent 2>/dev/null
info "npm run build..."
npm run build --silent 2>/dev/null
ok "前端编译完成"

# ─── 将前端 dist 复制到后端 embed 目录 ─────────────────────
step "打包前端到二进制"
rm -rf "$TMP_DIR/backend/frontend/dist"
cp -r "$TMP_DIR/frontend/dist" "$TMP_DIR/backend/frontend/dist"
info "前端已复制到 backend/frontend/dist，准备 embed"

# ─── 编译后端（embed 前端）──────────────────────────────────
step "编译后端（含嵌入前端）"
cd "$TMP_DIR/backend"
info "go build..."
GOFLAGS="-mod=mod" go build -ldflags="-s -w" -o nginxflow-server .
ok "后端编译完成（单一可执行文件）"

# ─── 部署文件 ────────────────────────────────────────────
step "部署到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"
cp "$TMP_DIR/backend/nginxflow-server" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/nginxflow-server"
ok "部署完成（仅一个可执行文件）"

# ─── 生成配置文件（仅首次）──────────────────────────────────
CFG="$INSTALL_DIR/config.yaml"
if [ ! -f "$CFG" ]; then
    step "生成配置文件"
    cat > "$CFG" << CFGEOF
server:
  port: $APP_PORT

nginx:
  conf_dir: /etc/nginx/conf.d
  reload_cmd: nginx -s reload
  test_cmd: nginx -t

db:
  path: $INSTALL_DIR/data/nginxflow.db

jwt:
  secret: "$JWT_SECRET"
CFGEOF
    ok "配置文件已生成: $CFG"
else
    warn "配置文件已存在，跳过（保留原有配置）"
fi

# ─── 配置 nginx 主文件 ───────────────────────────────────
step "配置 nginx"
NGINX_CONF="/etc/nginx/nginx.conf"
[ -f "$NGINX_CONF" ] && cp "$NGINX_CONF" "${NGINX_CONF}.bak.$(date +%Y%m%d%H%M%S)" && info "已备份原 nginx.conf"

STREAM_LOAD=""
if ! nginx -V 2>&1 | grep -q 'with-stream'; then
    [ -f /usr/lib/nginx/modules/ngx_stream_module.so ] && \
        STREAM_LOAD="load_module /usr/lib/nginx/modules/ngx_stream_module.so;"
fi

NGINX_USER="www-data"
id "$NGINX_USER" &>/dev/null || NGINX_USER="nginx"

cat > "$NGINX_CONF" << NGINXEOF
${STREAM_LOAD}

user $NGINX_USER;
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
    log_format combined_custom '\$remote_addr - [\$time_local] "\$request" '
                               '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent"';

    include /etc/nginx/conf.d/*-http.conf;
}

stream {
    log_format basic '\$remote_addr [\$time_local] '
                     '\$protocol \$status \$bytes_sent \$bytes_received '
                     '\$session_time "\$upstream_addr"';
    include /etc/nginx/conf.d/*-stream.conf;
}
NGINXEOF

nginx -t && ok "nginx 配置完成" || err "nginx 配置语法错误，请检查"

# ─── 配置 systemd 服务 ────────────────────────────────────
step "配置系统服务"
cat > /etc/systemd/system/nginxflow.service << SVCEOF
[Unit]
Description=NginxFlow Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/nginxflow-server -config $CFG
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable nginxflow
systemctl restart nginxflow
systemctl restart nginx

sleep 2
if systemctl is-active --quiet nginxflow; then
    ok "nginxflow 服务已启动"
else
    warn "nginxflow 启动异常，查看日志: journalctl -u nginxflow -n 30"
fi

# ─── 清理 ────────────────────────────────────────────────
rm -rf "$TMP_DIR"

# ─── 完成 ────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║          安装完成！                       ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  管理后台:  ${BOLD}http://${IP}:${APP_PORT}${NC}"
echo -e "  默认账号:  ${BOLD}admin${NC}  /  ${BOLD}admin123${NC}"
echo ""
echo -e "  常用命令:"
echo -e "  ${CYAN}systemctl status nginxflow${NC}   # 查看服务状态"
echo -e "  ${CYAN}journalctl -u nginxflow -f${NC}   # 实时日志"
echo -e "  ${CYAN}systemctl restart nginxflow${NC}  # 重启服务"
echo ""
echo -e "  ${YELLOW}首次登录后请修改默认密码${NC}"
echo ""
