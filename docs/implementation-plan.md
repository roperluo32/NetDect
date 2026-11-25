# NetDect 实现计划（M1–M3）

NetDect 是一个跨平台（Windows / macOS）桌面工具：点击「检测」，确认本机指定 AI 应用（默认 Claude）的所有流量都从选定的目标出口（如 Decodo 日本 ISP 代理 `japan01`）出去。全部符合显示绿色「正常」。

本文是 M1–M4 的实现计划。M1–M3 是一键检测，M4 是运行期实时守护（见第 9 节）。

---

## 1. 目标与判定标准

**检测对象**：选中应用的全部规则（来自 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) 的 `data/providers/*.yaml`），加上本机实际安装的该应用的所有可执行文件名。

**判定方法**（可信度从高到低）：

| 方法 | 做法 | 适用 |
| :--- | :--- | :--- |
| 实测 | 拿到真实出口 IP 与目标 IP 比对。域名：经系统网络请求 `https://<域名>/cdn-cgi/trace`（Cloudflare 站点会返回 `ip=`、`loc=`）；进程名：把 NetDect 自身复制为该进程名，以探针模式请求 IP 回显服务 | Cloudflare 站点、所有进程名 |
| 归因 | 探测连接建立后，按本地源端口在代理软件（mihomo / Clash 兼容 API）的 `/connections` 里找到这条连接，读出命中规则和代理链路；链路最终节点属于「已实测通过的节点」即判通过 | 其余域名、IP 段 |
| 抽样 | 关键词规则无法穷举，拼示例域名 `<关键词>.com` 后按域名处理，结果标注「抽样」 | `domainKeyword` |

**单项状态**：

- `pass`（绿）：实测 IP = 目标 IP；或归因节点 ∈ 已验证节点集合。
- `fail`（红）：实测 IP ≠ 目标 IP；或归因到 `DIRECT` / `REJECT` / 已知非目标节点。
- `warn`（黄）：无法验证（无 API 且非 Cloudflare、归因节点未被实测过、连接失败但无法确定原因）。
- `skip`（灰）：不适用（如本机无 IPv6 时的 IPv6 段、ASN 规则），不计入总评。

**总评**：无 `fail` 且无 `warn` → 正常（绿）；有 `fail` → 异常（红）；只有 `warn` → 部分未验证（黄）。

---

## 2. 技术选型

- **框架**：Tauri 2（Rust 后端 + React 19 / TypeScript / Vite 前端）。
- **Rust 依赖**：
  - `tokio`（异步运行时、并发、命名管道/Unix socket）
  - `tokio-rustls` + `webpki-roots`（自定义 SNI 的 TLS 握手）
  - `reqwest`（rustls + socks 特性：经 SOCKS5 获取目标出口 IP、HTTP 控制器 API、规则同步）
  - `serde` / `serde_json` / `serde_yaml`
  - `keyring`（Windows 凭据管理器 / macOS 钥匙串存储出口密码）
  - `sysinfo`（进程枚举）、`netdev`（网卡与默认路由）
  - `winreg`（Windows 系统代理）、`ipnet`（IP 段计算）
  - `tauri-plugin-dialog`（导出报告的保存对话框）
- **规则数据**：构建时由 `scripts/sync-providers.mjs` 拉取 VPSDance 全部 provider，生成 `src-tauri/resources/providers.json` 内置快照；运行时可在界面中「更新规则」，缓存到应用数据目录。

---

## 3. 目录结构

```
NetDect/
├─ docs/implementation-plan.md
├─ scripts/
│  ├─ sync-providers.mjs        # 生成内置规则快照
│  └─ gen-icon.mjs              # 生成应用图标源图
├─ src/                         # 前端
│  ├─ main.tsx / App.tsx / styles.css
│  ├─ api.ts                    # invoke / 事件封装
│  ├─ types.ts
│  └─ components/
│     ├─ TopBar.tsx             # 目标出口选择、检测按钮、总评指示灯
│     ├─ ExitsPanel.tsx         # 出口列表与增删改、刷新 IP
│     ├─ ExitDialog.tsx         # 新增/编辑出口（支持粘贴 host:port:user:pass）
│     ├─ AppsPanel.tsx          # 应用勾选、搜索、分类与地区筛选、更新规则
│     ├─ ResultsPanel.tsx       # 环境检查 + 各应用检测明细、导出
│     └─ SettingsDialog.tsx     # 代理软件 API、探测方式、并发、超时
└─ src-tauri/
   ├─ Cargo.toml / build.rs / tauri.conf.json
   ├─ capabilities/default.json
   ├─ resources/providers.json
   ├─ icons/
   └─ src/
      ├─ main.rs                # 入口：探针模式短路，否则启动 Tauri
      ├─ lib.rs                 # Tauri 命令注册与应用状态
      ├─ config.rs              # 配置读写、出口密码进钥匙串
      ├─ providers.rs           # 规则模型、内置快照、在线同步
      ├─ exits.rs               # 出口串解析、经 SOCKS5 获取出口 IP/国家
      ├─ env_check.rs           # 代理软件进程、TUN、系统代理、环境变量、IPv6
      ├─ discovery.rs           # 本机已安装应用可执行文件发现
      ├─ engine.rs              # mihomo/Clash 兼容 API：HTTP、命名管道、Unix socket
      ├─ net.rs                 # 探测连接：直连/HTTP 代理/SOCKS5、TLS、trace 解析
      ├─ probe.rs               # 进程名探针（复制自身 + --netdect-probe）
      ├─ checker.rs             # 检测编排：展开检测项、并发执行、归因、总评
      └─ report.rs              # 报告导出（JSON / Markdown）
```

---

## 4. 核心模块设计

### 4.1 出口配置（`config.rs`、`exits.rs`）

- 出口串格式 `host:port:user:pass`，按前三个冒号切分，密码可含冒号。
- 配置文件 `config.json` 存于应用配置目录（Windows `%APPDATA%\com.netdect.app`，macOS `~/Library/Application Support/com.netdect.app`）。只存 `id / name / host / port / username / pinned_ip / last_ip / last_country / last_org / last_checked`，**密码存系统钥匙串**（服务名 `NetDect`，账户为出口 id）。
- 获取出口 IP：reqwest 以 `socks5h://user:pass@host:port` 为代理，依次请求 `https://ipinfo.io/json`、`https://api.ipify.org?format=json`，得到 IP、国家、运营商。
- 本机直连 Decodo 失败时（国内网络可能拦截），可设置 `pinned_ip` 作为期望 IP。检测时优先级：`pinned_ip` > 最近一次成功获取的 `last_ip`；均无时提示先刷新。

### 4.2 规则库（`providers.rs`）

- 模型与 VPSDance 源数据一致：`provider / name / description / scope(global|cn) / categories / aliases / groups[].rules{domain, domainSuffix, domainKeyword, processName, ipCidr, ipCidr6, asn}`。
- 加载顺序：应用数据目录缓存 `providers.json`（在线更新后写入） > 内置快照。
- 在线更新：jsDelivr 目录 API `https://data.jsdelivr.com/v1/packages/gh/VPSDance/ai-proxy-rules@main?structure=flat` 列出 `/data/providers/*.yaml`，并发下载解析后整体替换缓存；任一步失败保留旧数据。

### 4.3 环境检查（`env_check.rs`）

| 检查项 | 方法 | 结果 |
| :--- | :--- | :--- |
| 代理软件 | 进程名匹配 clash-verge / verge-mihomo / mihomo / sing-box / ClashX / FlClash / mihomo-party / Surge 等 | 无则 fail |
| TUN | 默认路由所在网卡是否为隧道（Meta / Mihomo / utun / tun / wintun / sing） | 记录为探测方式依据 |
| 系统代理 | Windows 注册表 `Internet Settings`；macOS `scutil --proxy` | 记录 |
| 环境变量 | `HTTPS_PROXY / HTTP_PROXY / ALL_PROXY`（含小写） | 记录 |
| IPv6 旁路 | 非隧道网卡上存在全局 IPv6 地址 | warn |
| 代理软件 API | 能否读到 `/version` | 不可用则归因项降级为 warn |

### 4.4 探测连接（`net.rs`）

统一流程：建立 TCP（记录本地源端口）→ TLS（SNI = 目标域名；IP 目标用 IP 名称）→ 发送 `GET /cdn-cgi/trace HTTP/1.1` → 读取响应解析 `ip= / loc= / colo=`。

- **探测方式**（设置中选择，默认自动）：
  - `tun`：直接连接，域名解析走系统 DNS（TUN 的 fake-ip 才能生效）。
  - `system`：读取系统 HTTP 代理，先 `CONNECT host:443`。
  - `env`：读取 `HTTPS_PROXY` 等，支持 `http://` 与 `socks5://`。
  - `auto`：TUN 生效 → tun；否则系统代理开启 → system；否则环境变量存在 → env；否则 tun（相当于直连，检测会显示失败）。
- TCP 建立后立即并行发起归因查询（见 4.6），TLS/HTTP 失败不影响归因。

### 4.5 进程名探针（`probe.rs`）

- `main.rs` 在启动 Tauri 前检查参数 `--netdect-probe <json>`；命中则执行一次 IP 回显请求，把结果以一行 JSON 输出到 stdout 后退出。
- 主程序把自身复制到 `临时目录/netdect-probe/<随机>/<进程名>`（Windows 补 `.exe` 规则：若进程名本身带 `.exe` 则原样使用），带参数启动，读取输出后删除副本。
- **回显地址选择（对照实验）**：先用 NetDect 自身进程请求候选回显地址（`https://4.ipw.cn`、`https://myip.ipip.net/json`、`https://api.ipify.org`、`https://ipinfo.io/ip`），选第一个「基线 IP ≠ 目标 IP」的地址作为探针回显地址。这样探针拿到目标 IP 只能是进程规则生效的结果，而不是回显地址本身被代理。所有候选都等于目标 IP 时，进程项降级为 warn（无法区分）。
- 有 API 时同时归因，可显示命中规则（如 `ProcessName claude.exe → Claude → japan01`）。

### 4.6 代理软件 API（`engine.rs`）

- 接入方式：`http`（`http://127.0.0.1:9090` + secret）、Windows 命名管道、Unix socket；`auto` 时先枚举本机**实际存在**的 mihomo / clash 管道（Windows `\\.\pipe\`）或 socket（macOS `/tmp/verge` 等），再尝试 Clash Verge Rev `clash-verge.yaml` 里的 `external-controller`、`external-controller-pipe`、`external-controller-unix`，最后试 `127.0.0.1:9090 / 9097`；secret 取自同一文件。
  - 实测发现 yaml 里记录的管道名可能过期（本机记录为 `verge-mihomo-sidecar-release-…`，实际运行的是 `verge-mihomo-production-…`），所以优先用枚举结果。
- 管道与 Unix socket 上手写 HTTP/1.0 请求（避免分块编码），读到 EOF 后解析。
- `/connections` 返回 `metadata.sourcePort`（字符串）、`metadata.host`、`metadata.process`、`chains`（`chains[0]` 为最终节点）、`rule`、`rulePayload`。
- 归因：TCP 连上后、TLS 握手前先查一次（最多 0.8 s，每 120 ms 轮询，按 `sourcePort` 精确匹配）。对端拒绝握手时连接会立即关闭，握手后再查就看不到了；查不到时（例如依赖 SNI 嗅探才分流的配置）在握手期间再查一次，最多 2.5 s。
- sing-box 的 `clash_api` 与该接口兼容，配置为 `http` 方式即可接入（M3）。

### 4.7 本机应用发现（`discovery.rs`）

内置常见应用的位置表，可在配置中追加：

| provider | Windows | macOS |
| :--- | :--- | :--- |
| anthropic | MSIX 包 `Claude`（`Get-AppxPackage` 取安装目录）、`%LOCALAPPDATA%\AnthropicClaude`、`%USERPROFILE%\.local\bin` | `/Applications/Claude.app`、`~/.local/bin` |
| openai | MSIX 包 `OpenAI.ChatGPT-Desktop`、`OpenAI.Codex` | `/Applications/ChatGPT.app`、`/Applications/Codex.app` |
| cursor | `%LOCALAPPDATA%\Programs\cursor` | `/Applications/Cursor.app` |
| windsurf | `%LOCALAPPDATA%\Programs\Windsurf` | `/Applications/Windsurf.app` |

- 递归（深度 ≤ 6）收集可执行文件名：Windows 为 `.exe`；macOS 为 `Contents/MacOS/*` 与 `Contents/Frameworks/*.app/Contents/MacOS/*`（Electron 的 `Claude Helper` 系列）及带可执行位的 Mach-O。
- Claude Code 仅收集名为 `claude` / `claude.exe` 的文件，避免把整个 `.local/bin` 都当成 Claude。
- 同时扫描运行中进程：可执行路径位于上述目录下的进程名也加入。
- 与规则表 `processName` 合并去重；规则表未收录的进程名标记「规则表未收录」。
- 过滤通用进程名（`node`、`python`、`git`、`rg`、Chromium 的 `chrome_proxy` / `elevation_service` 等、`Uninstall*`），给这类名字加 PROCESS-NAME 规则会误伤其他软件。以应用名命名的辅助进程（如 macOS 的 `Claude Helper`，Electron 的网络服务就跑在里面）保留。
- 判定口径：规则表列出的进程走错出口为 fail；仅本机发现、规则表未收录的进程走错出口为 warn，并提示补 `PROCESS-NAME` 规则（工具无法知道它是否联网，如 `claude-make-data-folder.exe`）。
- 域名后缀探测失败（裸域不提供 HTTPS）时，改用 `www.<后缀>` 重试一次。

### 4.8 检测编排（`checker.rs`）

1. 读取配置，确定目标出口与期望 IP；
2. 环境检查，确定探测方式，探测代理软件 API；
3. 选回显地址（4.5）；
4. 展开检测项：每个 provider 的 domain / domainSuffix / domainKeyword（抽样）/ processName / 本机发现的进程名 / ipCidr（取段内第一个主机地址）/ ipCidr6（本机无 IPv6 则 skip）/ asn（skip，说明以 IP 段为代表）；
5. 并发执行（默认 8，超时 10 s），每完成一项通过 Tauri 事件 `check-progress` 推送；支持取消；
6. 第二轮判定：收集「实测通过」项的归因节点为已验证集合，「实测失败」项的节点为已知非目标集合，再判定仅有归因的项；
7. 汇总每个应用与整体状态，保存最近一次报告，支持导出 JSON / Markdown。

---

## 5. 界面

- **顶栏**：目标出口下拉（名称 · IP · 国家）、「检测 / 取消」按钮、进度、总评指示灯（正常 / 异常 / 部分未验证）。
- **左栏 · 出口**：列表显示名称、`host:port`、最近 IP 与国家；新增（粘贴串一键解析，可改名）、编辑、删除、刷新 IP、设为目标。
- **右上 · 应用**：搜索；地区（海外 / 国内）与分类（coding / model / media …）筛选；勾选，默认 Anthropic / Claude；「更新规则」显示规则版本时间。
- **右下 · 结果**：环境检查列表；每个应用可折叠，显示通过 / 失败 / 未验证计数；每项显示状态色、类型、目标、方法（实测 / 归因 / 抽样）、观测到的 IP 与地区、命中规则与链路、说明；「导出报告」。
- **设置**：代理软件 API（自动 / HTTP / 管道 / Unix socket、地址、secret、测试连接）、探测方式、并发、超时。

---

## 6. 里程碑与任务

### M1：单应用实测（Claude）

- [x] Tauri 2 + React 工程骨架、图标、构建脚本
- [x] 出口配置：解析、增删改、钥匙串存储、经 SOCKS5 获取 IP/国家、固定 IP
- [x] 内置规则快照（直接内置全量 102 个 provider）
- [x] 环境检查
- [x] 探测连接（tun / system / env）与 Cloudflare trace 实测
- [x] 进程名探针 + 回显地址对照实验
- [x] 检测编排、进度事件、取消、总评
- [x] 界面：顶栏、出口栏、结果栏

### M2：归因与本机发现

- [x] mihomo / Clash 兼容 API（HTTP、命名管道、Unix socket，Clash Verge 自动发现）
- [x] 按源端口归因、两轮判定
- [x] 本机应用可执行文件发现（MSIX、.app、Electron Helper、运行中进程）
- [x] 规则表未收录进程名提示
- [x] 报告导出（JSON / Markdown）
- [x] 设置对话框

### M3：多应用与 sing-box

- [x] 全量 VPSDance provider 快照 + 在线更新
- [x] 应用勾选、搜索、地区与分类筛选，默认 Claude
- [x] 多应用并发检测与分组结果
- [x] sing-box `clash_api` 接入说明与兼容处理（见 `docs/usage.md`）
- [x] Windows 与 macOS 打包配置（GitHub Actions 工作流 `.github/workflows/build.yml`）

---

## 7. 验证计划

在本机（Windows，Clash Verge Rev TUN，claude01 订阅）验证：

1. 出口 `japan01`（`isp.decodo.com:10001`）获取 IP 为 `203.0.113.10`、国家 JP；直连 Decodo 失败时固定 IP 生效。
2. Claude 检测：`claude.ai`、`anthropic.com` 实测 `203.0.113.10`；`claude.exe` 进程探针实测通过。
3. `cowork-svc.exe`：在 VPSDance 规则集未加载时应为 fail，加载后为 pass（与 `claude-egress-check.ps1` 结论一致）。
4. 目标改选 `japan02`（`104.252.126.215`）后，Claude 各项应为 fail，证明判定确实比对了目标 IP。
5. 代理软件 API 不可用时归因项为 warn，可用时可显示命中规则与链路。
6. `cargo check`、前端 `tsc` 类型检查、`tauri build` 生成 Windows 安装包。

macOS 无本机环境，打包由 GitHub Actions 完成，运行验证需在 Mac 上进行。

### 7.1 验证结果（2026-11-25，Windows）

检测引擎用 `src-tauri/examples/check.rs`（命令行，固定期望 IP）跑，和 GUI 走的是同一套 `checker::run`。

| # | 结果 | 说明 |
| :--- | :--- | :--- |
| 1 | 通过 | `isp.decodo.com:10001` 解析为 `203.0.113.10` · JP · AS2497 IIJ；钥匙串写入、读取、删除正常（`examples/exit_ip.rs`） |
| 2 | 通过 | `claude.ai`、`anthropic.com` 等实测 `203.0.113.10`；`claude.exe` 进程探针通过，命中 `ProcessName claude.exe → Claude → Claude 落地节点` |
| 3 | 符合预期 | VPSDance 规则集尚未加载（`ruleset/anthropic-vpsdance.yaml` 不存在），`cowork-svc.exe`、`modelcontextprotocol.*`、`cdn.growthbook.io`、`interface.feedback` 等均 fail，归因为 `Match → DIRECT`。加载后复测为待办 |
| 4 | 通过 | 目标改为 `104.252.126.215` 后 Anthropic 通过 0 项、失败 46 项，归因项判为「节点已实测不是目标出口」 |
| 5 | 通过 | 管道未找到时归因项为 warn；接上 `verge-mihomo-production-…` 管道（mihomo v1.19.33）后显示规则与链路，Anthropic 的 warn 由 25 项降到 7 项 |
| 6 | 通过 | `cargo test` 10 项通过、`tsc` 无错误、`tauri build` 生成 `netdect.exe`；窗口截图渲染正常 |

GUI 的点击操作（添加出口、勾选、导出）未做自动化验证：本次会话中桌面自动化工具不可用，只做了截图确认，相关命令的后端逻辑已经由上面的示例程序覆盖。

---

## 8. 已知限制

- MCP 子进程（`node`、`python` 等）无法与 Claude 区分，只覆盖它们访问规则表域名的流量。
- 非 Cloudflare 域名在无代理软件 API 时只能给出 warn。
- trace 中 `h=` 与所测域名不一致（例如 `modelcontextprotocol.io` 经 Vercel 转发，`h=docs.mintlify.builders`）时，`ip=` 是转发服务器的出口，丢弃该 trace 并改用归因。
- 关键词规则为抽样结论。
- 检测是主动探测，证明「这类请求会走目标出口」；应用实际发出的连接由 M4 实时守护覆盖。
- 本机直连 Decodo 获取出口 IP 可能被拦截，需固定 IP。

---

## 9. M4：实时守护（`guard.rs`、`tray.rs`）

检测只能证明「这类请求会走目标出口」；守护盯的是应用实际发出的每一条连接，并持续确认目标出口本身没有变。

### 9.1 工作方式

| 环节 | 做法 | 频率 |
| :--- | :--- | :--- |
| 连接监视 | 读代理软件 `/connections`，按连接 `id` 去重，只判定新出现的连接 | 默认每 1 s |
| 出口复核 | 用 Cloudflare trace 实测几个所选应用的域名，更新「节点 → 出口 IP」表；同时复查环境（TUN、IPv6 旁路等） | 默认每 5 min，另有「立即复核」 |
| 进程监视 | 扫描所选应用的进程；出现原本没在运行的进程名时记一条「启动了 X」并复核出口 | 每 3 s |
| 按需实测 | 连接走了从未实测过的节点、且有域名时，用同一域名实测一次，学到该节点的出口 IP | 每个节点一次 |

**连接匹配**（任一命中即属于该应用）：

- 进程：进程名在规则表 `processName` 或本机发现的进程名里，或进程路径位于应用安装目录下。这类连接**不论去哪**都必须走目标出口。
- 目的地：域名命中 `domain` / `domainSuffix` / `domainKeyword`，或目标 IP 在 `ipCidr` 内。不论哪个程序发起（例如浏览器访问 `claude.ai`）。
- 排除：局域网、回环、fake-ip 段（`198.18.0.0/15`）、CGNAT 段，mihomo 内部连接（`type = Inner`），以及 NetDect 自己的探测流量（检测时的端点探测和改名探针）。

**判定**（取 `chains[0]` 为节点）：

| 节点 | 结果 |
| :--- | :--- |
| 已实测且出口 = 目标 IP | 正常 |
| `DIRECT` / `PASS` | 泄漏（直连，出口是本机 IP） |
| 已实测但出口 ≠ 目标 IP | 泄漏 |
| `REJECT*` | 已拦截（没有发出，不算泄漏） |
| 从未实测 | 待确认；节点出口测出来后，原记录就地改判为正常或泄漏 |

节点出口 IP 的来源：上次「检测」中实测项的归因节点、定时复核、按需实测。

**出口复核的结论**：

- 失败：某个原本出口正确的节点，出口变了（例如中转机上的 sing-box 停了，落地端口改从中转机自己的 IP 出去）；或者没有一个复核域名到达目标出口。
- 通过但有提醒：个别复核域名走了别的出口，说明规则没覆盖它，记一条「规则覆盖提醒」，不判为出口故障。
- 无结论：复核域名都拿不到出口 IP（非 Cloudflare 站点）。运行过一次「检测」后，守护会改用检测中实测通过的域名。

**整体状态**：未开启 → 复核中 → 正常（绿）/ 待确认（黄）/ 告警（红：有泄漏、复核失败或环境异常）/ 错误（代理软件 API 连续 3 次无响应）。「清空」会重置计数。

### 9.2 告警与常驻

- 系统通知：泄漏、复核失败或恢复、环境异常、API 中断、应用启动后的复核结果。同一类告警 2 分钟内只通知一次，任意两条通知至少间隔 3 秒。
- 托盘：图标颜色随状态变化（灰 / 黄 / 绿 / 红），悬停显示状态和目标出口；菜单有显示窗口、开启 / 暂停守护、立即复核、退出。
- 守护开启时关闭窗口改为最小化到托盘（可关闭此行为）；完全退出用托盘菜单「退出」。
- 可选：打开 NetDect 时自动开启守护；开机自启（带 `--autostart` 参数，后台启动并开启守护）。
- 单实例：再次打开 NetDect 只会唤出已有窗口，避免两个守护同时运行。

### 9.3 任务

- [x] mihomo 连接字段补全（`id`、`processPath`、`sniffHost`、`remoteDestination` 等）
- [x] 守护循环：连接监视、去重、匹配、判定、待确认项改判
- [x] 出口复核：节点出口表、出口漂移检测、规则覆盖提醒、环境复查
- [x] 按需实测未知节点
- [x] 进程启动检测（按进程名，兼容常驻服务）与启动后复核
- [x] 系统通知与限流
- [x] 托盘、关闭到托盘、开机自启、单实例
- [x] 界面：「实时守护」标签页、顶栏状态、设置项

### 9.4 验证结果（2026-11-25，Windows）

用 `src-tauri/examples/guard.rs`（命令行守护，和 GUI 同一套 `Guard`）接真实 mihomo 运行，同时人为制造流量：

| 场景 | 结果 |
| :--- | :--- |
| 开启后复核 | `anthropic.com`、`chat.com` 实测出口 `203.0.113.10`，节点表学到「Claude 落地节点 = 203.0.113.10」 |
| curl 访问 `claude.ai`、改名为 `cowork-svc.exe` 的 curl 访问 `www.example.com` | 判为正常，命中 `RuleSet anthropic → Claude 落地节点`（anthropic 规则集已在 14:49 更新，含 `PROCESS-NAME,cowork-svc.exe`） |
| 改名为 `claude-ssh-broker.exe` 的 curl 访问 `www.example.com` | 判为泄漏（`Match → DIRECT`），并发出通知 |
| 同时守护 OpenAI | 抓到 Codex 包内 `ChatGPT.exe` 的两条真实直连：`arms-retcode-sg.aliyuncs.com`（`RuleSet direct`）、`safebrowsing.googleapis.com`（`RuleSet google`） |
| 启动阶段已存在的连接 | 先记为待确认，复核完成后全部就地改判，最终待确认 0 |
| OpenAI 复核域名 `ai.com` 走 DIRECT（香港出口） | 记为规则覆盖提醒，整体不判为出口故障 |
| GUI：启动即开启守护 | 状态绿色，节点表、监视应用、记录正常显示 |
| GUI：模拟启动 `claude.exe`（改名的 ping） | 记录「Anthropic 启动了 claude.exe」，3 秒内完成复核 |

未验证：系统通知在 GUI 里的实际弹出效果、托盘菜单的点击、开机自启（本次会话中桌面自动化工具不可用）。
