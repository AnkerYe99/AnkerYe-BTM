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

## 启动/恢复时的批量应用

`ApplyAll` 不再对每条启用规则分别运行 `nginx -t` 和 reload。新流程是：

1. 无副作用地渲染全部启用规则的 HTTP/stream 文件、规则回源 CA、logrotate、端口 catch-all 及其自签证书，并把发行版 nginx 默认站点表示为“应不存在”。
2. 所有应存在的文件先写入权限 `0700` 的私有暂存目录，再按文件集合和每个文件字节与磁盘比较。
3. 文件集合和内容完全相同时，不运行 `nginx -t`，也不 reload。若 nginx 未运行且存在启用规则，仍只 start 一次。
4. 有差异时，先在暂存区保存原文件字节/权限/符号链接目标，再逐文件原子替换；全部替换完后只运行一次 `nginx -t` 和一次 reload（nginx 未运行时为一次 start）。
5. 暂存、备份、写入或 `nginx -t` 任一步失败，恢复差异集中的全部原文件且不 reload。激活命令自身失败时也恢复磁盘文件，不会为“回滚”再发第二次 reload。

禁用规则的历史遗留文件仍按旧语义保留；只有显式的禁用/删除操作负责清理它们。端口 catch-all 的生成条件和清理范围不变。

程序启动入口 `backend/main.go` 与备份恢复入口 `backend/handler/settings.go` 都调用同一个 `ApplyAll`。仓库内没有其他“循环中逐条调用 `ApplyRule`”的批处理入口；规则 CRUD、后端节点 CRUD 和健康状态翻转仍是单规则事件，保持调用 `ApplyRule`。从节点全量同步使用独立的 `applyRulesFull`，不经过 `ApplyRule` 循环，本次不改其语义。

### nginx 官方行为依据

- [Controlling nginx](https://nginx.org/en/docs/control.html)：HUP/reload 时 master 先检查新配置并尝试打开新日志/监听套接字；失败则继续使用旧配置，成功后才启动新 worker 并优雅关闭旧 worker。
- [Command-line parameters](https://nginx.org/en/docs/switches.html)：`-t` 不只检查语法，还会尝试打开配置中引用的文件；`-s reload` 启动使用新配置的 worker，并优雅关闭旧 worker。
- [`worker_shutdown_timeout`](https://nginx.org/en/docs/ngx_core_module.html#worker_shutdown_timeout)：为 worker 的优雅关闭设置超时，到期后 nginx 尝试关闭尚未结束的当前连接。

## 健康状态一致性

健康检查的状态、连续成功/失败计数和跳变日志不再进入允许丢写的异步统计队列。同一规则的一轮探测使用一个同步数据库事务，事务提交成功后才按需调用一次 `ApplyRule`，因此恢复节点会在重新渲染前已经是 DB 中的 `up` 状态。

状态更新使用旧 state、server ID、rule ID 和探测时的端点做 compare-and-swap。并发人工禁用、删除或修改端点会使整轮事务回滚，不会被健康 worker 覆盖。一轮内多个节点同时跳变仍只应用一次配置；没有状态跳变时只持久化计数和检查时间，不触发 nginx reload。

若 `ApplyRule` 失败，其文件级回退完成后，健康检查会用本轮新状态和时间戳作为条件，在补偿事务中恢复更新前的数据库状态，并把失败写入跳变日志；成功生效前不会发送 up/down 通知。补偿事务自身失败会记录 `CRITICAL` 并触发强制运维邮件，避免 DB 与 nginx 的分歧被静默忽略。
