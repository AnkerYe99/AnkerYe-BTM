# AnkerYe - 流量管理 (AnkerYe-BTM)

基于 **Go + Gin + Vue3 + nginx + SQLite** 构建的轻量级流量管理平台，提供完整的 Web 可视化界面，支持 HTTP/HTTPS 反向代理、TCP/UDP 四层转发、主动健康检查、SSL 证书全自动管理、主从节点同步、在线升级等功能。

---

## 一键安装

### 公网（GitHub）

```bash
curl -sSL https://raw.githubusercontent.com/AnkerYe99/AnkerYe-BTM/master/install.sh | bash
```

自定义端口：

```bash
curl -sSL https://raw.githubusercontent.com/AnkerYe99/AnkerYe-BTM/master/install.sh | BTM_PORT=8080 bash
```

### 内网（Gitea）

```bash
GITEA_URL=http://10.14.6.51:3000 curl -sSL http://10.14.6.51:3000/anker/AnkerYe-BTM/raw/branch/master/install.sh | bash
```

自定义端口：

```bash
GITEA_URL=http://10.14.6.51:3000 curl -sSL http://10.14.6.51:3000/anker/AnkerYe-BTM/raw/branch/master/install.sh | BTM_PORT=8080 bash
```

> 脚本会自动优先尝试用户通过 `GITEA_URL` 指定的内网 Gitea，无法访问时自动回退到 GitHub。

---

## 安装后信息

| 项目 | 路径 |
|:--|:--|
| 安装目录 | `/opt/ankerye-btm/` |
| 配置文件 | `/opt/ankerye-btm/config.yaml` |
| 数据库 | `/opt/ankerye-btm/data/ankerye-btm.db` |
| 运行日志 | `/var/log/ankerye-btm/app.log` |
| systemd 服务 | `ankerye-btm` |

服务管理：

```bash
systemctl status  ankerye-btm
systemctl start   ankerye-btm
systemctl stop    ankerye-btm
systemctl restart ankerye-btm
```

查看日志：

```bash
journalctl -u ankerye-btm -f
tail -f /var/log/ankerye-btm/app.log
```

---

## 配置文件说明

`/opt/ankerye-btm/config.yaml`：

```yaml
server:
  port: 9000
  jwt_secret: "your-secret-key"

database:
  path: /opt/ankerye-btm/data/ankerye-btm.db

nginx:
  conf_dir: /etc/nginx/conf.d
  reload_cmd: nginx -s reload
  test_cmd: nginx -t
  log_dir: /var/log/ankerye-btm
```

> 升级时配置文件不会被覆盖，安全保留。

---

## 在线升级

登录 Web 界面 → 系统设置 → 检查更新 → 一键升级。

也可以通过 API 触发：

```bash
# 检查是否有新版本
curl -H "Authorization: Bearer <token>" http://HOST:PORT/api/v1/update/check

# 执行升级（服务会在约 3 秒后自动重启）
curl -X POST -H "Authorization: Bearer <token>" http://HOST:PORT/api/v1/update/apply
```

内网环境可在系统设置中配置 `update_gitea_url`，升级时优先从内网 Gitea 拉取。

---

## 从源码构建

```bash
git clone http://10.14.6.51:3000/anker/AnkerYe-BTM.git
# 或
git clone https://github.com/AnkerYe99/AnkerYe-BTM.git

cd AnkerYe-BTM

# 构建前端
cd frontend
npm install
npm run build:embed
cd ..

# 构建后端（含嵌入前端静态文件）
cd backend
go build -o nginxflow-server .
```

HTTPS 回源的字段、兼容策略和升级顺序见 [HTTPS_UPSTREAM.md](HTTPS_UPSTREAM.md)。

---

## 目录结构

```
AnkerYe-BTM/
├── install.sh              # 一键安装脚本
├── README.md
├── frontend/               # Vue3 + Tailwind 前端
│   ├── src/
│   └── dist/               # 构建产物（嵌入二进制）
└── backend/                # Go 后端
    ├── main.go
    ├── config/
    ├── db/
    ├── engine/             # nginx 配置生成、健康检查、同步
    ├── handler/            # HTTP 路由处理器
    ├── health/
    ├── middleware/
    ├── model/
    └── util/
```

---

## 默认账号

| 账号 | 密码 |
|:--|:--|
| admin | admin123 |

首次登录后请立即修改密码。

---

## 仓库地址

| | 地址 |
|:--|:--|
| 内网 Gitea | http://10.14.6.51:3000/anker/AnkerYe-BTM |
| 公网 GitHub | https://github.com/AnkerYe99/AnkerYe-BTM |
