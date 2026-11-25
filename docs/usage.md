# NetDect 使用说明

NetDect 用来确认：本机所选 AI 应用的流量，是否都从你指定的那个代理出口（例如 Decodo 日本 ISP IP）出去。全部通过时结果栏显示绿色。

## 1. 安装与构建

- Windows：运行 `netdect_x.y.z_x64-setup.exe`，或直接运行 `src-tauri\target\release\netdect.exe`。
- macOS：打开 `NetDect_x.y.z_universal.dmg`。未签名的包首次打开需在「系统设置 → 隐私与安全性」里放行。
- 自己构建：

```powershell
npm install --registry=https://registry.npmmirror.com
npm run tauri build          # 生成安装包
npm run tauri dev            # 开发模式
cargo test --manifest-path src-tauri/Cargo.toml
```

推送 `v*` 标签会触发 `.github/workflows/build.yml`，同时产出 Windows 安装包和 macOS 通用 dmg（草稿 Release）。

## 2. 基本流程

1. **添加出口**：左栏「添加」，把 `isp.decodo.com:10001:用户名:密码` 粘贴进「快速粘贴」框，填一个名字（如 `japan01`），保存。
   - 密码存放在系统钥匙串（Windows 凭据管理器 / macOS 钥匙串），服务名 `NetDect`，不写入配置文件。
   - 默认保存后立即经该代理请求一次 `ipinfo.io`，得到出口 IP、国家和运营商。
   - 本机连不上 Decodo，或者想锁死某个 IP 时，填「固定出口 IP」，检测会以它为准。
2. **选目标出口**：点出口卡片，或在顶栏下拉里选择。
3. **勾选应用**：中栏默认只勾 Anthropic（Claude）。支持按名称或别名搜索，也可按海外 / 国内、编程 / 模型 / 多媒体筛选。
4. **检测**：点顶栏「检测」。结果边测边显示，结束后给出总评，可「导出报告」（`.md` 或 `.json`）。

## 3. 怎么读结果

| 状态 | 含义 |
| :--- | :--- |
| 通过 | 这条流量的出口就是目标 IP |
| 失败 | 出口不是目标 IP，或被分到 DIRECT / REJECT |
| 未验证 | 无法确认，比如对端不提供 HTTPS 或连接失败；或者是本机发现、规则表没收录的辅助进程走了别的出口 |
| 跳过 | IPv6 段、ASN 这类无法单独探测的规则 |

「方法」一列：

- **实测**：通过 Cloudflare 的 `/cdn-cgi/trace` 看到真实出口 IP；进程项则是把 NetDect 复制成同名进程，再去请求 IP 回显服务。有些站点由别的服务器（如 Vercel）转发到 Cloudflare，trace 里的 `h=` 不是所测域名，`ip=` 是转发服务器的 IP。NetDect 会丢弃这类 trace，改按节点归因，备注里写明“站点经其他服务器转发”。
- **归因**：从代理软件 API 查到这条连接命中的规则和最终节点，再和实测通过的节点比对。
- **抽样**：关键词规则（如 `sentry`）没法穷举，用 `<关键词>.com` 代表测一次。

「命中规则 → 节点」一列直接告诉你该改哪里，例如 `Match → DIRECT` 表示这个域名没有规则覆盖，落到了最后的兜底规则。

## 4. 实时守护

「检测」是一次性的主动抽查；「实时守护」在后台持续盯着所选应用实际发出的每一条连接。

1. 右栏切到「实时守护」，点「开启守护」，或在托盘菜单里开启。需要能连上代理软件 API（见第 5 节）。
2. 开启后会先复核一次目标出口：实测几个所选应用的域名，确认它们从目标 IP 出去，并记下「节点 → 出口 IP」。先运行过一次「检测」的话，复核会直接用检测里实测通过的域名，结论更可靠。
3. 之后每秒读取一次代理软件的连接列表。所选应用的新连接会被判定：

| 状态 | 含义 |
| :--- | :--- |
| 正常 | 走的节点已实测从目标 IP 出去 |
| 泄漏 | 直连，或走的节点出口不是目标 IP。会弹系统通知 |
| 待确认 | 走的节点还没实测过；守护会尝试按需实测，测出来后自动改判 |
| 已拦截 | 被 REJECT 规则拦下，没有发出 |

「属于所选应用」有两种认法：按进程（进程名或安装目录下的程序，例如 Claude 包里的 `cowork-svc.exe`），这类连接去哪都必须走目标出口；按目的地（规则表里的域名、IP 段），哪个程序发起的都算，比如浏览器访问 `claude.ai`。

4. 每 5 分钟（可调）复核一次出口和环境。目标出口本身出问题时（例如中转服务器的 sing-box 停了，日本出口变成了香港 IP），守护会变红并通知。
5. 所选应用有新进程启动时（比如打开 Claude Desktop），守护会立即复核一次出口并通知结果。这就是「打开 Claude 前确认出口」的自动版本。

托盘和后台运行：

- 托盘图标颜色：灰 = 未开启，黄 = 复核中或有待确认，绿 = 正常，红 = 告警。
- 守护开启时关闭窗口只会最小化到托盘；要完全退出，用托盘菜单「退出」。
- 设置里可以打开「打开 NetDect 时自动开启守护」和「开机自动启动」（后台启动并开启守护）。

限制：

- 守护依赖代理软件 API。代理软件退出或 API 无响应时，守护会变红并通知，但这段时间的流量看不到。
- 连接列表是轮询的，存活时间短于轮询间隔（默认 1 秒）的连接可能漏掉。需要更严时把间隔调到 300–500 毫秒。
- 不经过代理软件的流量（例如没开 TUN 时直连的程序）不会出现在连接列表里，这类问题靠「检测」和环境检查发现。

## 5. 代理软件 API

归因和实时守护都需要连接代理软件的控制接口。设置里默认是「自动发现」：

- **Clash Verge Rev**：自动枚举本机正在运行的 mihomo 命名管道或 Unix socket，secret 从 `clash-verge.yaml` 读取，一般无需配置。
- **mihomo / Clash 核心**：选「HTTP 地址」，填 `external-controller` 的地址（如 `127.0.0.1:9090`）和 `secret`。
- **sing-box**：在配置里开启 `clash_api`，然后在 NetDect 里选「HTTP 地址」：

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "换成你自己的密钥"
    }
  }
}
```

sing-box 的 `/connections` 与 mihomo 格式兼容：`chains[0]` 是最终出站（例如 `jp-1`），`rule` 是命中的路由规则，NetDect 按源端口匹配，不需要额外处理。

API 不可用时检测照常进行（守护则无法工作），只是非 Cloudflare 站点会更多地显示为「未验证」。

## 6. 探测方式

| 选项 | 适用 |
| :--- | :--- |
| 自动 | 有 TUN 时直接连接；否则用系统代理；再否则用 `HTTPS_PROXY` / `ALL_PROXY` |
| 直连 | 代理软件开了 TUN（虚拟网卡）模式 |
| 系统代理 | 只开了系统代理（Windows 注册表 / macOS `scutil --proxy`） |
| 环境变量 | 命令行工具类场景，例如只给 Claude Code 设了 `HTTPS_PROXY` |

注意：只开系统代理时，不遵守系统代理的程序（例如 Claude Code 等 CLI）实际上是直连，进程项会如实显示为失败。

## 7. 常见问题

- **`cowork-svc.exe` 等失败、规则显示 `Match → DIRECT`**：代理配置里没有覆盖它。可以在 Clash 配置里加入 VPSDance 的规则集（`https://cdn.jsdelivr.net/gh/VPSDance/ai-proxy-rules@main/rules/clash/anthropic.yaml`），修改后记得在 Clash Verge 里重新激活该订阅，让规则集下载生效。
- **「刷新 IP」失败**：本机连 Decodo 被拦截或代理认证失败。可以在出口里填「固定出口 IP」。
- **某些域名一直「未验证」**：这类域名多半只是规则表里的占位，裸域不提供 HTTPS（例如 `modelcontextprotocol.com`），不影响实际使用。
- **配置文件位置**：设置对话框底部会显示，Windows 一般在 `%APPDATA%\com.netdect.desktop\config.json`，macOS 在 `~/Library/Application Support/com.netdect.desktop/config.json`。
