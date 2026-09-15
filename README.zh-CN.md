# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

CLIProxyAPI 的隐私过滤插件：请求发给模型前把密钥、Token、密码、邮箱、IP 等敏感值替换成占位符，响应回来时再还原成真实值。
敏感值只保存在本机 CPA 进程内存里，从不上云；模型照常能把它们写进命令、代码和配置。

学 AI 就上 L 站：[linux.do](https://linux.do/)。

本项目基于 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
实现核心过滤能力，并适配 [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的 CPA 插件 ABI。

## 作用

当 CLIProxyAPI 收到请求时，插件会在请求离开本地进程前扫描支持的文本字段，把检测到的敏感值换成确定性占位符
（如 `pf-key-3a7f9c21d0b4`）；模型的回复（含流式文本和工具调用参数）经过插件时，占位符再被换回真实值。

典型场景：

- 防止 API Key 和 Token 意外泄露
- 在提示词发送给模型前移除个人联系方式
- 对 LLM 请求流量应用 Gitleaks 风格的密钥检测
- 将过滤逻辑保留在 CLIProxyAPI 插件链路内

## v0.4.0：可逆替换

v0.3.0 及以前把敏感值替换成固定标签 `[密钥]` / `[邮箱]`，模型拿不到值，只能在命令、配置里写出 `[密钥]`，
编码代理的后续工作流因此一直失败。v0.4.0 改为可逆替换：

| 环节 | 做法 |
| --- | --- |
| 占位符 | `<前缀>-<类型>-<12 位 hex>`，由本地 HMAC 密钥对值计算，同一值永远得到同一占位符，重放历史不破坏 prompt cache。类型为 `key`/`email`/`phone`/`idcard`/`ip`/`card`。可选 `uuid` 样式。 |
| 映射表 | 只在 CPA 进程内存（vault），不落盘；磁盘上只有 `data_dir/placeholder.key`（0600）用于保持占位符稳定。 |
| 请求侧 | before-auth 检测并替换；检测范围收窄到值本身（`GITHUB_TOKEN=ghp_…` 只替换 `ghp_…`，键名留给模型）；已识别过的值在请求体任何字符串里再次出现都会被替换（包括检测器不读的字段、`scan_tool_input: false` 时的工具参数；长度 ≥8 的密钥不要求词边界，覆盖 `-p<密码>` 这类写法）。 |
| 响应侧 | 非流式整体还原；流式按协议处理 delta（含 Codex 走的 Responses WebSocket 下游），占位符被拆在多个 delta 里时暂存尾部，块结束前补发；工具参数（JSON 文本）里的值按 JSON 转义还原。只还原本请求上游请求体里出现过的占位符，上游模型无法靠吐出别的会话的占位符把值拉进来。 |
| 不还原 | `thinking` / `redacted_thinking` / `reasoning` 及签名：它们会被原样回传，改动会让签名失效，所以保留占位符。 |
| 提示 | 请求含占位符且开启还原时，在系统提示词末尾追加一段英文说明，让模型把占位符当作值原样使用（措辞刻意中性：实测写成“受保护机密”会让模型拒绝使用）。 |

为什么默认不用 UUID：UUID 约 24 个 token，[boundaryml 的实测](https://boundaryml.com/blog/uuid-swap) 里模型复制 UUID 的错误率显著高于短 ID；
主流实现（LLM Guard、llmasking-go、Kong AI Sanitizer）也都用“类型+短 ID”。固定前缀还能让响应侧对不含占位符的文本零成本跳过。

已验证：Claude Messages / OpenAI chat / OpenAI Responses / Gemini 四种客户端协议 × Claude / OpenAI 两种上游协议 × 流式/非流式，
上游收到的请求体无明文，客户端收到的文本与工具参数均为真实值；真实模型（MiniMax-M3、DeepSeek）能用占位符完成写配置类任务。

已知限制：

- vault 在内存里，CPA 重启后清空。重启后首个请求会从历史里重新识别；但若某个值的“可识别上下文”已不在历史中（如被 compact 掉），
  它在其他上下文里再次出现时可能识别不到。
- vault 不按客户端分区：请求体里带着某个已知占位符的客户端会被当作它的持有者。多个互不信任的用户共用一个 CPA 时不要依赖它做隔离。
- CPA 7.3.3 的 gemini→claude 翻译会丢弃 `systemInstruction`，此组合下模型收不到提示说明（替换与还原不受影响）。

## 本 fork 的改动（v0.3.0）

本 fork（v0.3.0）针对编码代理流量做了重写：Claude Code、Codex、opencode、antigravity 的请求体常在几十 KB 到几 MB，
而且每一轮都会把整段会话重发一遍。完整清单与基准数据见 [CHANGELOG.md](CHANGELOG.md)，要点如下：

- **覆盖面**。上游只走 `messages[].content[].text`。在一个 229KB 的 Claude Code 请求上，它实际只扫了 3.6KB（1.6%）：
  `tool_result` 输出、`tool_use` 参数、`system` 提示词、Responses 的 `input` 条目以及 Gemini 的全部字段都未过滤就发了出去。
  本 fork 覆盖 Claude Messages、OpenAI chat、OpenAI Responses、Gemini `generateContent`，同一请求体扫描 197KB。
- **只跑一个钩子**。上游在 before-auth 和 after-auth 两个拦截钩子里跑了同一套改写逻辑。after-auth 的请求体是 before-auth
  请求体做格式翻译的结果，第二遍不可能扫出新东西，只是把成本翻倍，且每次重试都会重复。现在只有 before-auth 做脱敏。
- **字节级原位改写**。上游把整个 body 反序列化再序列化，会打乱字段顺序、重新转义字符串——即使那条消息根本没被改动。
  本 fork 只把命中的字符串字面量拼回原始字节，不破坏 prompt cache 与供应商签名；thinking 块一律不动。
- **更快的引擎**。检测逻辑移到 `internal/scan`：一次 Aho-Corasick 扫描取代约 290 次 `strings.Contains` 关键词预筛，
  字节类信号会跳过证明不可能命中的整条正则，高熵兜底正则由预扫描直接产出。语义完全一致——
  `internal/scan/parity_test.go` 会逐样本比对上游库的输出。
- **内容缓存**。扫描结果按 SHA-256 记忆，会话里重发的历史只扫一次，而不是每轮一次；字段之间并行扫描。
- 新增配置：`disable_rules`、`max_body_bytes`、`scan_tool_input`、`cache_entries`、`cache_bytes`、`workers`、
  `log_stats`。默认值保持原有检测行为。

Ryzen 9 5900X 实测，同一个 229KB 的 Claude Code 请求：同等覆盖面下旧引擎 117.0ms，新引擎单线程 75.0ms，
默认 4 worker 21.5ms；会话稳定态（缓存已装载重放历史）2.1ms。

## 功能

- CLIProxyAPI 插件运行时的请求拦截器
- 脱敏邮箱、手机号、身份证、银行卡、IP、密钥、连接串、证书等敏感内容
- 使用内置 Gitleaks 规则 `rules/gitleaks.toml`（已编译进共享库）
- 支持自定义 Gitleaks 规则文件，也支持按规则 id 关闭
- 支持 Claude Messages、OpenAI chat、OpenAI Responses、Gemini 请求体
- 可按模型名、来源格式或请求体大小跳过过滤
- 可构建为 Linux、macOS、Windows 原生共享库

## 环境要求

- Go 1.26+
- 启用 CGO
- 已安装 `make`

## 构建

克隆并构建：

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter

make build
```

默认构建把共享库输出到仓库根目录：

- Linux：`privacyfilter.so`
- macOS：`privacyfilter.dylib`
- Windows：`privacyfilter.dll`

`make dist` 则按 CPA「从文件名推导插件 id」的命名约定输出可部署产物及校验和：

```bash
make dist
# dist/privacyfilter-v0.4.0.so
# dist/privacyfilter-v0.4.0.so.sha256
```

指定平台构建：

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

用 `BUILD_DIR` 改变 `make build` 的输出目录：

```bash
BUILD_DIR=dist make build
```

## 在 CLIProxyAPI 中使用

把共享库放到 CLIProxyAPI 的插件目录。Gitleaks 规则已经编译进二进制，不需要额外文件：

```text
privacyfilter/
└── privacyfilter.so        # 或 privacyfilter.dylib / privacyfilter.dll
```

然后在 CLIProxyAPI 中启用 `privacyfilter` 插件。

插件元信息：

- 名称：`privacyfilter`
- 能力：`RequestInterceptor`（仅 before-auth 钩子）、`ResponseInterceptor`、`StreamChunkInterceptor`、`RequestLifecyclePlugin`
- 作者：`rheodev, szxypi`

### 本机安装（systemd 部署）

`ops/deploy` 会把产物装进以 `cliproxy` 用户运行的 CPA、删掉旧版本、重启服务，并轮询 journal 等待注册日志：

```bash
make dist
sudo ops/deploy            # 或：sudo ops/deploy 0.4.0
```

它假定的是原生 systemd 部署的目录结构：

- 插件目录 `/var/lib/cli-proxy-api/plugins/linux/amd64/`
- 配置 `/var/lib/cli-proxy-api/config.yaml`
- 服务单元 `cli-proxy-api.service`

CPA 从文件名推导插件 id（`privacyfilter-v0.4.0.so` → `privacyfilter`），并且**会直接忽略 `plugins.configs` 里没有对应
条目的库**，所以重启前配置必须先写好；`ops/deploy` 检查不到条目会直接拒绝执行。改 `config.yaml` 要原地改写，
用 rename 覆盖会让 CPA 的配置 watcher 跟丢文件。

## 配置

插件配置写在 CLIProxyAPI 主配置文件（`config.yaml`）里。`plugins.configs.<id>` 下，宿主字段（`enabled`、`priority`）
由 CLIProxyAPI 消费，其余 YAML 子树原样传给插件。

推荐配置：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      priority: 10
      # 占位符样式：short（pf-key-3a7f9c21d0b4）或 uuid
      placeholder_style: short
      # 响应里把占位符还原成真实值；关闭即变成单向替换
      restore_responses: true
      # 含占位符时在系统提示词末尾追加英文说明
      notice: true
      # 只存占位符 HMAC 密钥，不存敏感值；相对路径基于 CPA 工作目录
      data_dir: privacyfilter
      # 不替换的类型：key、email、phone、idcard、ip、card
      # skip_types: [ip]
      # 超过该大小的请求体直接放行不扫描；-1 表示不限制
      max_body_bytes: 4194304
      # 除消息正文外，也扫描工具调用参数与工具结果
      scan_tool_input: true
      # 记住扫过的文本；编码代理每轮都会重放整段历史
      cache_entries: 4096
      cache_bytes: 67108864
      workers: 4
      # 打开后可省掉约 60% 的扫描耗时（generic-api-key 也是误报最多的规则），
      # 其余规则不受影响
      # disable_rules:
      #   - generic-api-key
      # log_stats: true
```

插件字段：

| 字段                | 类型      | 默认值        | 说明                                                          |
|-------------------|---------|------------|-------------------------------------------------------------|
| `placeholder_style` | string | `short` | `short`（`pf-key-3a7f9c21d0b4`）或 `uuid`（v8 UUID）。改动会让所有占位符变化。 |
| `placeholder_prefix` | string | `pf` | short 样式的前缀，1-16 位小写字母或数字。 |
| `restore_responses` | boolean | `true` | 在非流式/流式响应里还原占位符。 |
| `notice`          | boolean | `true`     | 请求含占位符时在系统提示词末尾追加说明。 |
| `skip_types`      | array   | `[]`       | 不替换的类型（`key`/`email`/`phone`/`idcard`/`ip`/`card`）。 |
| `data_dir`        | string  | `privacyfilter` | 占位符 HMAC 密钥目录，相对 CPA 工作目录。 |
| `vault_max_entries` | integer | `100000` | 内存映射表上限，超出按最久未见淘汰。 |
| `literal_min_bytes` | integer | `6` | 已识别值在其他上下文再次出现时也替换的最小长度（最小 4，按词边界匹配）。 |
| `gitleaks_toml`   | string  | `""`       | 自定义 gitleaks 规则文件路径，相对路径基于插件目录解析。                |
| `skip_models`     | array   | `[]`       | 跳过脱敏的模型（同时匹配路由后模型与客户端请求的模型）。            |
| `skip_formats`    | array   | `[]`       | 跳过脱敏的来源格式。                                             |
| `disable_rules`   | array   | `[]`       | 按 id 关闭 gitleaks 规则。`generic-api-key` 约占 60% 耗时且误报最多。 |
| `max_body_bytes`  | integer | `4194304`  | 超过该字节数的请求体不扫描。`-1` 表示不限制。                        |
| `scan_tool_input` | boolean | `true`     | 是否扫描工具调用参数与工具结果。                                    |
| `cache_entries`   | integer | `4096`     | 跨请求记住的文本条数，`0` 关闭缓存。                                |
| `cache_bytes`     | integer | `67108864` | 检测结果缓存的字节预算（只存偏移，不存值）。                          |
| `workers`         | integer | `4`        | 扫描单个请求字段的并发数，上限为 `NumCPU`。                          |
| `log_stats`       | boolean | `false`    | 无命中的请求也打一条 debug 日志；命中始终按 info 记录。               |

当 `gitleaks_toml` 为空且没有 `rules/gitleaks.toml` 旁文件时，插件使用编译进二进制的内置规则。

## 工作方式

请求（before-auth 钩子，原位改写请求体）：

1. 检查 `skip_models`、`skip_formats`、`max_body_bytes`。
2. 校验 body 是合法 JSON，并按格式感知的收集器遍历。
3. 第一阶段：并行检测各文本字段（结果按内容哈希缓存），收窄到值本身，过滤代码形态的误报与回环/掩码 IP，登记进 vault。
4. 第二阶段：替换检测到的值，并对 vault 中已知的值做一次按词边界的字面量匹配。
5. 把改写后的字符串字面量拼回原始字节，其余字节原样复制；按 RequestID 暂存本请求的“占位符→值”表；含占位符时追加提示说明。

响应：

1. 非流式：按 JSON 遍历模型输出字段还原，跳过 thinking/reasoning 与签名；`arguments` / `partial_json` 按 JSON 转义还原。
2. 流式：header-init 时重置流状态（CPA 的 bootstrap 重试会重来一次），逐 chunk 按协议处理：
   Claude 事件流的 `text_delta` / `input_json_delta`、OpenAI chat 的 `delta.content` / `tool_calls[].function.arguments`、
   Responses 的 `output_text.delta` / `function_call_arguments.delta` / `custom_tool_call_input.delta`、Gemini 的 `parts[].text`。
   delta 末尾可能是占位符前缀时暂存，下个 delta 拼上再还原；块结束时 Claude/Responses 补发一个 delta 事件，OpenAI/Gemini 合并进结束 chunk。
3. `request.complete` 生命周期回调清理状态；没有占位符的请求在 ABI 层直接返回，不解码 chunk。

after-auth 钩子是有意的空实现：那里的 payload 只是 before-auth 已过滤 body 的格式翻译，再扫一遍每次尝试都要多付一整轮
成本，却不可能扫出新东西。

会扫描的字段：

| 格式 | 字段 |
| --- | --- |
| Claude Messages | `system`（字符串或块）、`messages[].content`（字符串或块）、`text` 块、`tool_result.content`（字符串/块/嵌套 text）、`tool_use.input` 内的字符串 |
| OpenAI chat | `messages[].content`（字符串或数组）、`tool_calls[].function.arguments`、`function_call.arguments` |
| OpenAI Responses | `instructions`、`input`（字符串或条目）、`input_text` / `output_text`、`function_call_output.output` |
| Gemini | `contents[].parts[].text`、`systemInstruction` / `system_instruction`、`functionCall.args`、`functionResponse.response` |

有意跳过的：`thinking` / `redacted_thinking` / `reasoning` 块（带供应商签名，必须原样回传）、内联 base64（图片、音频、
文件），以及 `tool_use_id`、各类 id、role、模型名等结构性标识。

支持的请求形态示例：

```json
{
  "model": "claude-sonnet-5",
  "system": [{"type": "text", "text": "You are Claude Code."}],
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "tool_result", "tool_use_id": "toolu_01", "content": [{"type": "text", "text": "GITHUB_TOKEN=ghp_xxx"}]}
      ]
    }
  ]
}
```

```json
{
  "model": "gpt-5",
  "input": "My GitHub token is ghp_xxx"
}
```

## 规则

内置规则在构建时从以下文件嵌入共享库：

```text
rules/gitleaks.toml
```

运行时规则解析顺序：

1. 配置项 `gitleaks_toml`（如已设置）
2. 共享库同级的 `rules/gitleaks.toml` 旁文件
3. 构建时嵌入的规则（默认）

更新内置规则并重新构建：

```bash
make update-rules
make build
```

也可以用 `gitleaks_toml` 指定自己的规则文件：

```yaml
gitleaks_toml: custom/gitleaks.toml
```

相对路径基于插件目录解析。

## 开发

常用命令：

```bash
make test                                   # go vet ./... && go test ./...
make bench                                  # 全部基准测试，10 次迭代
make dist                                   # dist/privacyfilter-v<version>.so + .sha256
python3 integration_abi_test.py dist/privacyfilter-v0.4.0.so
```

`integration_abi_test.py` 通过真实 C ABI 加载编译产物（`cliproxy_plugin_init`、`plugin.register`、
`request.intercept_before`、`request.intercept_after`、`plugin.reconfigure`），验证脱敏结果、字节级改写与
after-auth 空实现。

主要文件：

```text
main.go                       插件元信息与构建入口
abi.go                        CLIProxyAPI 插件 ABI 适配
interceptor.go                钩子接线、并行扫描、统计
payload.go                    格式感知的 JSON 遍历与字节级拼接
config.go                     YAML 配置与规则加载
internal/scan/scan.go         扫描器、预扫描、脱敏
internal/scan/ac.go           Aho-Corasick 关键词自动机
internal/scan/detect.go       从 packyme/privacy-filter 移植的检测逻辑
internal/scan/rules.go        Gitleaks 规则加载
internal/scan/cache.go        内容缓存
rules/gitleaks.toml           内置检测规则
ops/deploy                    本机 systemd 安装脚本
```

依赖说明：

```text
privacyfilter => github.com/packyme/privacy-filter   # 测试中的一致性基准
```

## 来源

- 核心过滤逻辑：[packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
