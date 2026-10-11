# 跨层契约实施规范（v2.0）

> 契约源：`proto/control.proto`。本文件定义实现层的传输映射、ID 规范与行为约定。
> 修改契约的顺序：先改 proto → 再改本文件 → 再改三层实现。

## 1. 传输映射（v2.0：JSON over HTTP/127.0.0.1）

v2.0 用 JSON 承载 proto 消息（字段名与 proto 逐字一致，snake_case）。
选择理由：本机无 MSVC/protoc 工具链约束下先保证三层可编译可跑通；gRPC 为升级路径，
消息定义零变更。**JSON 只走 127.0.0.1，禁止对外监听。**

| 方向 | 方法 | 路由 | 说明 |
|---|---|---|---|
| Go → Rust | POST | `http://127.0.0.1:<ctrl_port>/snapshot` | 全量快照，原子生效 |
| Go → Rust | POST | `http://127.0.0.1:<ctrl_port>/policy` | 增量策略 |
| Go ← Rust | GET | `http://127.0.0.1:<ctrl_port>/events` | SSE 事件流（长连接） |
| Go ← Rust | GET | `http://127.0.0.1:<ctrl_port>/metrics` | 指标快照 |
| Go ← Rust | GET | `http://127.0.0.1:<ctrl_port>/health` | 存活检查 |
| Python → Go | POST | `http://127.0.0.1:8891/internal/verdict` | 研判回写 |
| Go → Python | POST | `http://127.0.0.1:8892/judge` | 事件入队（立即 202） |

### 认证

Rust 控制口启动时由 Go 生成 32 字节随机 token（hex），通过环境变量
`PG_CTRL_TOKEN` 传入 Rust；Go 请求携带 `Authorization: Bearer <token>`。
token 不落盘、不进日志。

### 端口约定

| 端口 | 归属 | 用途 |
|---|---|---|
| 8888 | Rust | 用户流量入口（HTTP 代理） |
| 8890 | Rust | 内部控制口（默认；`PG_CTRL_PORT` 可覆盖） |
| 8891 | Go | 管理 API / 指标 / verdict 回写入口 |
| 8892 | Python | 研判服务 |

## 2. trace_id 规范

- 格式：`pg-<unix_ms_base36>-<8位随机hex>`，示例 `pg-m3k2x1-9f3ab2c7`。
- 生成点：Rust 数据面在请求进入时生成，**只注入本地日志与事件**；
  不传给上游服务器（避免行为指纹）。
- 贯通：Rust 日志 → Thr�еatEvent.trace_id → Go 日志（转发时引用）→
  Python 研判记录 JSONL（`trace_id` 字段）→ Go verdict 回写。
- 日志格式统一为 `[trace=<id>] <component> <message>` 前缀，便于三进程日志联查。

## 3. 版本与一致性

- `ConfigSnapshot.version` 单调递增；Rust 收到 `version <= current` 时拒绝
  并返回 `accepted=false`。快照整体原子替换，不允许半套配置生效。
- `PolicyDelta.base_version` 若不等于 Rust 当前版本，Rust 返回
  `accepted=false`，Go 需回退为全量快照重推。
- 数据面自持原则：Go 断开时 Rust 继续用最后快照运行；事件流断开后
  Rust 侧丢弃超过背压上限的事件（不阻塞数据路径）。

## 4. 事件流行为

- Rust → Go 为 SSE；事件按行 `data: {json}\n\n`。
- 背压：Rust 侧事件通道容量 256；满则丢弃最旧的并计数
  （`extras.events_dropped` 上报），**数据面转发路径永不等待事件消费**。
- Go 重连策略：指数退避（1s 起步，上限 30s），重连后重新 `GET /metrics`
  对齐状态。

## 5. 行为对照锚点（行为不漂移）

Rust 检测引擎必须与 Python 参照实现（`core/detectors.py`）逐条对齐：

- 同一 `rules/*.yaml`（Rust 用 serde_yaml 加载，规则文件不改格式）。
- 对照测试集：`tests/test_sqli_mitm.py` + 规则样本 → 判定必须一致。
- 启发式阈值：Base64 ≥2000 字符且熵 >4.5；hex ≥400 且熵 >3.5；
  `String.fromCharCode` 计数 >8。
