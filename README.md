# Proxy Guard Agent

对接公共代理池的防护型本地 HTTP 代理。
**v2 架构**：Rust 高性能/安全核心（数据面）· Go 控制面与网络服务 · Python AI Agent 与插件生态。

> ⚠️ **仅用于低风险、匿名读取、可失败可丢弃的场景。** 公共代理默认不可信，不要用来访问重要账号或传输敏感数据。

---

## 架构（v2）

```
                     ┌───────────────────────────────────┐
   客户端 / 浏览器 ───▶│  Rust 数据面            :8888      │
                     │  转发 · CONNECT 隧道 · 检测引擎     │
                     │  域名路由 · 轮换执行 · SSRF · 红线   │
                     │  CSP 注入 · 熔断 · 事件外发         │
                     └───────┬──────────────────▲────────┘
                             │ 快照 / 增量策略     │ 事件流 (SSE)
                             ▼ （JSON over 127.0.0.1）
                     ┌───────────────────────────────────┐
                     │  Go 控制面              :8891      │
                     │  池抓取 / 验证 / 评分 / 轮换决策     │
                     │  快照生成下发 · 事件转发 · verdict  │
                     └───────┬──────────────────▲────────┘
                             │ /judge（事件）      │ verdict 回写
                             ▼                   │
                     ┌───────────────────────────────────┐
                     │  Python AI 层           :8892      │
                     │  LLM 研判队列 · 插件框架 · 规则生成  │
                     └───────────────────────────────────┘
```

### 三条铁律

1. **数据面自持**：Go 挂掉，Rust 用最后快照继续转发；Python 挂掉只丢研判不丢流量。
2. **AI 永不阻塞**：Python 交互全部异步、可超时、可丢弃，永不进关键路径。
3. **Go 是唯一配置源**：`config.yaml` 只被 Go 读取；Rust/Python 的策略来自快照下发。

### 轮换的"决定权 / 执行权"分离

- **慢循环（Go）**：抓取 / 验证 / 评分 / 健康检查 → 生成候选池与策略参数快照。
- **快路径（Rust）**：每请求出口选择 + **失败即时切换**（本地冷却，不等 Go 往返）。

### 目录结构

```
proxy-guard/
├── proto/control.proto      # 跨语言契约（唯一共享物）
├── core-rs/                 # Rust 数据面
├── ctrl-go/                 # Go 控制面（池管理吸收自 proxy-tui）
├── ai-py/                   # Python AI / 插件层
├── docs/contract.md         # 传输 / trace_id / 行为对照规范
├── docs/README-v1.md        # v1 版文档（参照实现）
├── rules/                   # 共享规则（Rust 执行，Python 可生成建议规则）
├── core/ + main.py          # v1 Python 单体（保留为行为对照参照实现）
└── config.example.yaml      # 配置模板（含 v2 新增 ctrl 段）
```

---

## 快速开始（v2）

### 方式一：下载即用（Windows x64）

从 [Releases](https://github.com/xwkpkp/proxy-guard-v2/releases) 下载
`proxy-guard-v2-windows-x64.zip`，解压后开两个终端：

```powershell
# 终端 A：数据面
.\proxy-guard-core.exe --listen 127.0.0.1:8888 --ctrl-port 8890 --rules rules

# 终端 B：控制面
.\guardctl.exe run -c config.yaml
```

Python AI 层为可选组件（需要 Python 3.10+），步骤见包内 `START-HERE.txt`。

### 方式二：从源码构建

```bash
# 1) Rust 数据面（需要 Rust 工具链）
cd core-rs && cargo build --release

# 2) Go 控制面（需要 Go 1.23+）
cd ctrl-go && go build -o bin/guardctl ./cmd/guardctl

# 3) Python AI 层
cd ai-py && pip install -r requirements.txt
```

> **Windows 无 MSVC 环境的构建要点**（本仓库在 GNU 工具链下验证通过）：
> - rustup 安装 `stable-x86_64-pc-windows-gnu`；
> - 链接器指向 llvm-mingw 的 `x86_64-w64-mingw32-clang.exe`；
> - 必须开启 `-Clink-self-contained=yes`（走 rustc 自带的 libgcc.a / libgcc_eh.a；
>   llvm-mingw 是 compiler-rt 系，不提供 libgcc）；
> - 通过 `[env]` 为 windows-sys 提供 `DLLTOOL` / `AR` / `RANLIB`（指向 llvm-mingw bin）。

### 运行（三进程）

```bash
# 1) Rust 数据面（先起，控制口等 Go 连接）
./core-rs/target/release/proxy-guard-core \
    --listen 127.0.0.1:8888 --ctrl-port 8890 --rules rules

# 2) Go 控制面（读 config.yaml，推送快照）
./ctrl-go/bin/guardctl run -c config.yaml

# 3) Python AI 层（可选；LLM 未配置时队列空跑）
python -m proxyguard_ai -c config.yaml
```

把浏览器/程序 HTTP 代理设为 `127.0.0.1:8888` 即可。

### 配置

复制 `config.example.yaml` 为 `config.yaml`。v2 新增 `ctrl` 段：

```yaml
ctrl:
  rust_url: "http://127.0.0.1:8890"   # Rust 控制口
  ctrl_token: ""                       # 空=不校验（仅限本地开发）
  api_listen: "127.0.0.1:8891"         # Go 管理 API
  snapshot_interval_s: 30              # 快照重推周期
  ai_url: "http://127.0.0.1:8892"      # Python 研判服务
```

---

## v2.0 覆盖范围

**已实现**（行为对照 v1 参照实现）：

| 能力 | 归属 | 状态 |
|---|---|---|
| HTTP 转发 + CONNECT 隧道 | Rust | ✅ |
| 检测引擎（13 签名 + 15 流量规则 + 启发式） | Rust | ✅（与 v1 同规则文件、对照测试一致） |
| SQLi 语义检测（18 模式，path+body，URL 解码视图对齐 v1） | Rust | ✅ |
| 域名路由（直连后缀/白名单/强制代理） | Go 决策 + Rust 执行 | ✅ |
| 出口轮换 + 失败即时切换（本地冷却） | Rust | ✅ |
| SSRF 拦截（全量网段对齐 v1） | Rust | ✅ |
| 数据红线（8 模式 + 敏感头，阻断语义） | Rust | ✅ |
| 响应注入检测 + CSP 注入 | Rust | ✅ |
| 熔断器 | Rust | ✅ |
| 快照 / 策略下发 + 事件流（SSE）+ verdict 回写 | 三端闭环 | ✅ |

**未覆盖（路线图）**：

- **MITM HTTPS 解密**（rcgen + rustls，下一里程碑；`mitm_enabled` 策略位已预留）；
- 大响应流式直通（当前缓冲上限 32MB，超过返回 502）；
- 每出口限速（RateLimiter）；
- DNS rebinding 二次校验（SSRF 目前只查 IP 字面量与元数据主机名）；
- 出口黑名单自动填充（验证中发现内容注入的代理；机制已预留，当前为空集）；
- 日志脱敏的完整对齐。

---

## 测试

```bash
# Rust：39 项（检测对照 / 路由 / 出口选择 / 快照版本 / 防护 / URL 解码）
cd core-rs && cargo test

# Go：池 / 验证 / 抓取 / 配置
cd ctrl-go && go test ./...

# Python：队列 / HTTP 端点 / 插件（端到端，无网络）
cd ai-py && python tests/test_flow.py
```

行为对照锚点：`rules/*.yaml` 三端共享；SQLi 样本判定与 v1 `tests/test_sqli_mitm.py` 一致；
契约与 trace_id 规范见 `docs/contract.md`。

---

## v1 Python 单体（参照实现）

`core/` + `main.py` 保留原 Python 实现，作为行为对照参照与回退形态。详细文档见 `docs/README-v1.md`：

```bash
pip install -r requirements.txt
python main.py --test-shield   # 离线自测检测引擎
python main.py                 # 启动（监听 127.0.0.1:8888）
```

## 安全须知

- **`cert_store/` 里的 CA 私钥绝不提交**（已 gitignore）。
- 公共代理可能记录/篡改/注入流量，本工具做了检测但无法保证绝对安全。
- 不要用公共代理登录重要账号、传密码/Token/支付信息（红线会拦截，但别依赖）。
- v2 控制口只监听 127.0.0.1；生产配置请设置 `ctrl.ctrl_token`。

## License

MIT
