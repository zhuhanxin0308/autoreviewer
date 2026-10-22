# CLI 适配说明

适配器负责配置一个已安装的 CLI、选择模型、启动非交互审计，并提取最终回答。它不安装或更新 CLI。请自行安装官方发行版本，并使用 `autoreviewer doctor` 检查可执行文件是否可用。

## 协议和版本要求

| `agent` | 默认命令 | `api_format` | `base_url` 示例 |
| --- | --- | --- | --- |
| `opencode` | `opencode` | `openai-chat` | `https://openrouter.ai/api/v1` |
| `codex` | `codex` | `openai-responses` | `https://api.openai.com/v1` |
| `claude` | `claude` | `anthropic` | `https://api.anthropic.com` |
| `gemini` | `gemini` | `gemini` | `https://generativelanguage.googleapis.com` |

这些地址展示协议对应关系，不代表平台授权，也不承诺模型可用或免费。Anthropic 使用服务根地址，由 CLI 附加 `/v1/messages`；Gemini 使用根地址，由 SDK 附加版本和资源路径。OpenAI 兼容平台通常使用带 `/v1` 的接口根地址。使用代理服务时以该服务文档为准，不要填具体的 `/chat/completions` 请求路径。

| CLI | 初始适配依据 | 运行约束 |
| --- | --- | --- |
| OpenCode | v1.2.27 源码、文档及 NVIDIA/GPT-OSS、Nemotron 小样例实测 | 独立配置、非交互运行、只读工具限制 |
| Codex CLI | 本地 0.163.0 帮助及配置解析验证 | 自定义 Responses provider、read-only sandbox、禁止交互审批 |
| Claude Code | 当前官方 CLI 文档 | 需要 **2.1.248+** 的 `--restricted`，以及 `--safe-mode`；只开放 Read/Glob/Grep，禁用 MCP |
| Gemini CLI | 当前 upstream main 文档与源码 | plan 模式、读取工具白名单，禁用 hooks/MCP/skills |

以上是适配依据，不是完整的线上兼容性认证。`doctor` 不验证 CLI 版本，也不请求模型平台；请特别检查 Claude Code 版本。旧版本不支持必要参数时应升级或使用受控自定义包装程序，不要通过放开执行权限来绕过。

OpenAI Chat Completions 与 Responses 不是同一种接口；Anthropic Messages 和 Gemini API 也有不同的消息、认证和工具调用格式。适配器会拒绝已知协议不匹配的配置。即便协议匹配，服务仍需支持 CLI 使用的工具调用和流式输出。将 OpenAI Chat Completions 平台用于 Claude/Gemini 需要外部协议转换服务，MVP 不提供转换代理。

## 独立实例

每个实例使用独立代码副本、HOME 和状态目录。密钥通过环境传入，不放入 CLI 命令行。项目内的 agent 配置不会复制到审计副本，标准适配器使用 CLI 提供的非交互模式和只读限制。

四种内置适配器均通过统一审计提示词接收随包附带的 [Cloudflare 审计指导适配](audit-guidance.md)，无需在 CLI 中安装原生 skill。项目指令与原生 skill 自动加载的限制保持不变，指导不会授予执行目标代码、PoC 或测试的权限。

这些限制取决于具体 CLI 版本，并不是统一的操作系统权限模型。CLI 仍可能具备进程级文件与网络访问能力。自定义 CLI 不自动继承标准适配器的权限限制。

内置适配器可以通过 `command = ["/path/to/opencode"]` 等配置覆盖启动命令。内置适配器不接受额外 `args`，以免改写必要限制；需要不同启动方式时使用自定义适配器。

## 自定义 CLI

可通过 `custom` 接入其他 agent 或包装脚本。命令以参数数组执行，不通过 shell 解释。

```toml
[agents.custom]
command = ["my-audit-cli"]
args = ["--model", "{model}", "--base-url", "{base_url}", "--prompt", "{prompt}"]

[[models]]
id = "custom-reviewer"
provider = "router"
model = "your-model-id"
agent = "custom"
```

参数占位符包括 `{model}`、`{base_url}`、`{workspace}`、`{prompt}` 和 `{output_file}`。可用环境变量为 `AUTOREVIEWER_API_KEY`、`AUTOREVIEWER_MODEL`、`AUTOREVIEWER_BASE_URL`、`AUTOREVIEWER_WORKSPACE`、`AUTOREVIEWER_OUTPUT_FILE` 和 `AUTOREVIEWER_AUDIT_PROMPT`。不支持将密钥插入命令行，工作目录是当前模型的审计副本。

`{prompt}` 包含完整审计要求、指导和输出格式；`AUTOREVIEWER_AUDIT_PROMPT` 始终提供同一提示词，因此不使用 `{prompt}` 参数的已有包装程序也可通过环境变量读取。包装程序必须选择其中一种方式将提示词传给模型。报告中的指导来源记录只能说明主程序交付了提示词，无法确认包装程序实际消费了它。

包装程序必须以成功退出码结束，默认在 stdout 输出 [发现 JSON](architecture.md#发现的数据约定)。如果参数包含 `{output_file}`，则应将最终 JSON 写入该路径。日志应写入 stderr。自定义命令是受信任程序，它负责自身权限、协议和工具调用行为。

## 当前验证范围

自动化测试覆盖命令构造、协议检查、输出解析和模拟子进程运行。Codex 配置通过本地 CLI 解析；Claude Code 和 Gemini CLI 参数参考上游资料。Codex、Claude Code、Gemini CLI 尚未通过真实模型审计验证。

2026-10-22 另进行了 NVIDIA 真实接口测试：OpenCode 1.2.27 使用 `openai/gpt-oss-20b` 和 `nvidia/nemotron-3.5-lightning-30b-a3b` 获得成功模型结果，耗时分别为 43.081 秒和 22.797 秒，均报告 41 行人工构造样例中预期的 SQL 注入和路径遍历，未报告安全 SQL 对照。GPT-OSS 在双模型并行批次中完成，但同批 Nemotron 输出路径校验失败，整体状态为 `partial`。Nemotron 后续单独重试才成功，没有修改生产代码；重试的诊断记录包含读取目录、读取源码文件、输出最终回答的工具调用流程。

其他候选模型出现过超时或模型请求 404，不能仅凭模型目录或工具调用探测通过就认定完整审计可用。后续又实测了五个和八个独立 CLI 进程并行：八模型批次中五个完成审计，两个失败，一个超时，整体仍为 partial。GPT-OSS 在新一轮出现工具调用和输出事件流错误，DiffusionGemma 在后续工具消息回传时返回 HTTP 400，说明单次成功或探测通过不代表持续兼容。见 [并发实测记录](live-tests/nvidia-parallel-2026-10-22.md)、[早期记录](live-tests/nvidia-2026-10-22.md) 和 [NVIDIA 配置示例](../examples/nvidia.toml)。

这次验证只覆盖上述 CLI、模型、接口和样例组合，不是模型能力排名，也不能证明所有仓库、模型或供应商都已兼容。

CLI 升级可能改变参数、配置优先级、认证方式和输出结构。报告问题时请提供 autoreviewer 版本、CLI 版本、adapter、协议类型，以及去除密钥和私密源码后的错误信息。不要上传 token 或完整环境变量列表。

上游资料：[OpenCode](https://opencode.ai/docs/) · [Codex CLI](https://developers.openai.com/codex/cli/) · [Claude Code](https://code.claude.com/docs/en/cli-reference) · [Gemini CLI](https://geminicli.com/docs/)
