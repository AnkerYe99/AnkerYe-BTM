# HTTPS 回源能力说明

本版本为 HTTP 类型规则增加规则级 HTTPS 回源。默认值保持旧行为：`upstream_protocol=http`、`proxy_read_timeout=60`；未启用新能力的既有规则生成文本和同步指纹不变。

## 字段

| API 字段 | 默认值 | 说明 |
|---|---:|---|
| `upstream_protocol` | `http` | `http` 或 `https`，只控制 BTM 到后端的连接 |
| `proxy_ssl_name` | 空 | HTTPS 回源的 SNI/证书校验名；空时取 `server_name` 中第一个精确 DNS 名 |
| `proxy_ssl_verify` | `1` | `1` 严格校验证书；`0` 仅供受控测试 |
| `proxy_ssl_trusted_ca_pem` | 空 | 空时使用系统 CA；非空时只接受公开的 CA `CERTIFICATE` PEM，最大 256 KiB |
| `proxy_ssl_verify_depth` | `5` | 证书链校验深度，范围 1–10 |
| `proxy_read_timeout` | `60` | 回源读取静默超时，单位秒，范围 1–86400 |

自定义 CA 原子写入 nginx 证书目录下的 `_upstream_ca/rule-<ID>.pem`。切回系统 CA、禁用或删除规则时，程序只清理对应规则的托管 CA 文件，不触碰证书中心的证书或私钥。

## 兼容性

- 数据库迁移版本为 v10。
- 新从节点在规则同步请求中上报 `caps=https_upstream_v1`。
- 新主节点只有在全部新字段为默认值时才允许旧从节点继续同步；一旦存在 HTTPS 回源或非默认读取超时，旧从节点收到 HTTP 409 `upgrade_required`，并保留最后一份可用配置。
- 新节点收到旧 wire format 时把缺失字段补为安全默认值。
- 规则指纹保留原 `R:`/`S:` 行；仅非默认规则追加 `U1:` 行。

## TLS 行为

HTTPS 回源固定启用 SNI，并限制为 TLS 1.2/1.3。证书校验默认开启。主动健康检查使用与真实回源相同的协议、SNI、CA 和校验策略；HTTPS 握手或证书失败不会降级为 TCP 存活。

配置写入、CA 写入、`nginx -t` 和 reload 失败时会恢复旧文件。从节点在应用新规则前先校验完整 payload 和 CA，旧节点不会接收无法理解的活动字段。

## 升级顺序

同一同步组应先升级主节点和全部从节点，保持所有新字段为默认值并确认指纹收敛，再激活 HTTPS 回源。不要在仍有旧从节点时启用新字段。
