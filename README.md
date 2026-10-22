# autoreviewer

通过本机 code agent CLI，让多个模型并行审查代码，汇总安全线索，并在人工审阅后发布 GitHub Issue。

**当前为 Alpha / MVP。** 提供本地 Web 界面和命令行；真实模型验证目前集中在 OpenCode + NVIDIA。模型发现均待核实，不代表已确认漏洞。

[English](README.en.md) · [Web 使用说明](docs/web-ui.md) · [CLI 适配](docs/cli-adapters.md) · [审计指导](docs/audit-guidance.md) · [架构](docs/architecture.md) · [安全说明](SECURITY.md)

## 快速开始：本地 Web 界面

需要 **Python 3.11+、Git**，以及自行安装的至少一种 [agent CLI](#模型与-cli)。当前主要面向 Linux/macOS；CLI 应能从 `PATH` 调用，也可在配置中指定可执行文件。autoreviewer 负责调度已有 CLI，模型服务由你配置的平台提供。

```bash
git clone https://github.com/zhuhanxin0308/autoreviewer.git
cd autoreviewer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
autoreviewer ui --open
```

打开 `http://127.0.0.1:8765`：

1. 配置平台的 `base_url`、协议、API Key，以及该平台实际可用的模型 ID；为每个模型选择 CLI。
2. 新建扫描，填写本地目录或 GitHub HTTPS 仓库地址，选择模型与并发数。
3. 查看每个模型的状态、活动和阶段结果；筛选发现，下载 JSON/Markdown 报告。需要发 Issue 时，先预览并明确确认发布。

每个模型拥有独立进程、代码副本、配置和 HOME，运行受并发及超时限制。界面支持取消扫描、恢复已保存的阶段结果、以新任务重试失败模型、导入报告，以及并排查看同位置候选；原始记录与失败状态保留。当前 UI 一次运行一个扫描任务，任务内可并行多个模型。

非敏感配置默认保存到 `autoreviewer.toml`，任务历史在 `.autoreviewer/ui/jobs/`。密钥可从环境变量读取；在界面输入的密钥只保留于服务进程内存，重启后需重新输入。服务只监听 `127.0.0.1`，面向本机单用户；本地路径指运行服务的机器。更多操作见 [Web 使用说明](docs/web-ui.md)。

## 模型与 CLI

可以配置多个平台，并为每个平台添加多个模型。一个 `[[models]]` 条目对应一个审计实例；模型 ID、免费额度、价格和可用性以平台当前规则为准。

| CLI / `agent` | `api_format` | 当前适配与验证边界 |
| --- | --- | --- |
| [OpenCode](https://opencode.ai/docs/) / `opencode` | `openai-chat` | OpenAI Chat Completions 兼容接口；以 **1.2.27** 完成 NVIDIA 真实模型测试 |
| [Codex CLI](https://developers.openai.com/codex/cli/) / `codex` | `openai-responses` | 需要 Responses 接口；按 **0.163.0** 检查本地配置解析，尚无真实模型审计验证 |
| [Claude Code](https://code.claude.com/docs/en/cli-reference) / `claude` | `anthropic` | 需要 Anthropic Messages 接口及 **2.1.248+** 的 `--restricted`、`--safe-mode`；尚无真实模型审计验证 |
| [Gemini CLI](https://geminicli.com/docs/) / `gemini` | `gemini` | 需要 Gemini 接口；按上游文档/源码适配 plan 模式与读取工具白名单，尚无真实模型审计验证 |
| 自定义包装程序 / `custom` | 由包装程序处理 | 接入其他 CLI；权限、协议和提示词交付由受信任的包装程序负责 |

**只改 `base_url` 不能转换协议。** Chat Completions 平台应选择 OpenCode；Claude/Gemini 接入此类平台需要外部协议转换服务。服务还须支持 CLI 所需的工具调用与流式输出。版本升级可能改变行为，详见 [CLI 适配说明](docs/cli-adapters.md)。

## 从命令行扫描

完成上面的安装后，创建配置；如果已经通过 UI 保存配置，可以直接编辑现有文件：

```bash
autoreviewer init --output autoreviewer.toml
```

以下是双模型配置示例。将两个 `model` 占位值替换为平台实际提供的模型 ID，在当前终端或密钥管理器设置 `OPENROUTER_API_KEY`。配置文件只填写密钥的**环境变量名**。

```toml
version = 1

[scan]
concurrency = 2
timeout_seconds = 600

[providers.router]
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"
api_format = "openai-chat"

[[models]]
id = "reviewer-a"
provider = "router"
model = "replace-with-available-model-id"
agent = "opencode"

[[models]]
id = "reviewer-b"
provider = "router"
model = "replace-with-another-model-id"
agent = "opencode"
```

增加 `[providers.NAME]` 可接入其他平台，模型的 `provider` 引用对应名称；每个模型配置 `id` 必须唯一。完整选项见 [配置示例](examples/autoreviewer.toml)；NVIDIA 用户可用 [NVIDIA 示例](examples/nvidia.toml)，并设置 `NVIDIA_API_KEY`。

```bash
autoreviewer doctor --config autoreviewer.toml

# 扫描本地目录
autoreviewer scan ./your-project --config autoreviewer.toml --output ./audit-local

# 扫描 GitHub 仓库的指定分支
autoreviewer scan https://github.com/OWNER/REPO.git --ref main \
  --config autoreviewer.toml --output ./audit-remote
```

添加 `--model reviewer-a` 可只运行指定配置，该参数可重复。`doctor` 检查配置、可执行文件和密钥是否存在，不验证 CLI 版本、模型服务连通性或权限。

结果为 `report.json` 和 `report.md`。`--output` 目录必须尚不存在；省略时在 `.autoreviewer/runs/` 创建独立目录。退出码 `0` 表示所有模型运行完成，与发现数量无关；`2` 表示配置错误或部分/全部失败；Ctrl+C 保存已完成结果并取消未完成实例，返回 `130`（保存要求输出位置可写）。

## 无密钥演示

在项目根目录运行，不需要 agent CLI 或模型 API Key：

```bash
autoreviewer scan examples/demo-repository \
  --config examples/demo.toml --output ./demo-result
```

演示启动两个本机 Python 模拟进程，返回固定的 `DEMO ONLY` 发现，用于体验调度、去重和报告流程；它不分析代码，也不请求模型。重复运行请使用新输出目录。

## GitHub Issue：先预览，再发布

将配置指向有权操作的仓库，并将 token 放入 `GITHUB_TOKEN` 环境变量：

```toml
[github]
repository = "OWNER/REPO"
token_env = "GITHUB_TOKEN"
labels = []
```

建议使用限定到目标仓库的 fine-grained token：私有源码读取需要 **Contents: Read**，创建 Issue 需要 **Issues: Read and write**，并允许仓库元数据读取。仓库须开启 Issues。公共仓库扫描通常不需要 token；配置中的标签必须已存在，或保留空列表。

```bash
# 只生成本地预览，不访问 GitHub
autoreviewer publish ./audit-local/report.json --config autoreviewer.toml

# 审阅后提交
autoreviewer publish ./audit-local/report.json --config autoreviewer.toml --yes
```

扫描不会自动发 Issue。部分失败报告需要显式 `--allow-partial`，全失败报告不能发布。发布会核对已有发现指纹，并保存 `github-publications.json` 回执；请保留回执供后续去重，已关闭 Issue 不会重开。独立客户端仍可能并发竞争。公开 Issue 会公开问题细节，敏感漏洞应使用仓库的私密报告渠道。流程与真实测试见 [架构说明](docs/architecture.md#发布边界) 和 [GitHub 实测记录](docs/live-tests/github-2026-10-23.md)。

## Cloudflare 审计指导

默认嵌入 [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) 的只读适配，固定提交 `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`。指导要求追踪信任边界、入口到危险操作的完整路径、已有防护和反证，并给出源码证据与最小修复建议。

指导随包提供，无需额外安装 skill 或运行时下载。四种内置 CLI 使用统一提示词；自定义包装程序必须转交 `{prompt}` 或 `AUTOREVIEWER_AUDIT_PROMPT`。报告逐模型记录来源、提交、适配版本及指导/提示词摘要；旧报告不会补写当前版本。这些记录不证明模型遵守了指导。

当前 `guidance-readonly` 不运行目标代码、测试或 PoC，不修改目标文件，也未实现上游完整的多阶段独立验证流程。所有发现保持 `unverified`，严重程度是暂定影响评估。集成和升级方式见 [审计指导说明](docs/audit-guidance.md)。

## 已验证范围

当前 **248 项 Python 自动化测试**及 Chromium 浏览器流程检查通过，覆盖调度、解析、报告、恢复、重试、指导来源、UI 与发布流程。自动化使用模拟 CLI 和 GitHub 接口，不等于所有真实 CLI/模型组合都通过。

| 真实测试 | 结果与范围 |
| --- | --- |
| [接入指导后的三模型审查](docs/live-tests/cloudflare-guidance-three-2026-10-22.md) | OpenCode + NVIDIA 审查固定提交的 `clipboard.js`；首轮 **1/3** 模型报告有效，含原样重试后 **2/3** 有效，共 3 模型、5 次进程尝试。Muse 的 1 条候选需宿主验证，采纳新漏洞 **0**、新增 Issue **0**；整体仍部分完成，无人工修复回答 |
| [历史五/八模型并发](docs/live-tests/nvidia-parallel-2026-10-22.md) | 41 行人工样例；五并发 2 个模型完成，八并发 5 个完成、2 个失败、1 个超时，均保留部分失败报告；[复现配置](examples/nvidia-parallel.toml) |
| [GitHub 集成](docs/live-tests/github-2026-10-23.md) | 真实仓库拉取、测试 Issue 创建、重复发布与重启后关闭状态去重 |

这些是有范围限制的集成测试，不是准确率或稳定性基准。不同轮次的目标与提示词范围不同，不能用发现数量比较指导效果；目前没有证据证明接入指导提高了检出率。

## 结果与安全边界

发现是**待人工核实的安全线索**；模型一致不等于验证成功，空报告不代表代码安全。报错、超时和无效输出会保留为失败，不能解释为“没有问题”。

快照默认过滤常见密钥文件、Git 元数据、符号链接和 agent 项目配置，过滤也会缩小审计范围。独立副本与 CLI 只读策略不构成操作系统沙箱，自定义 CLI 是受信任程序。代码会发送到所选模型服务，请只使用有权审计且允许发送的代码。详见 [SECURITY.md](SECURITY.md)。

## 文档、贡献与许可

[Web 界面](docs/web-ui.md) · [配置示例](examples/autoreviewer.toml) · [CLI 适配](docs/cli-adapters.md) · [审计指导](docs/audit-guidance.md) · [架构与数据约定](docs/architecture.md) · [贡献指南](CONTRIBUTING.md)

```bash
python -m unittest discover -s tests -v
```

浏览器测试的安装与运行见 [贡献指南](CONTRIBUTING.md)。欢迎改进适配器、真实兼容性验证、报告与审阅体验；提交问题时请附脱敏错误和版本信息。

项目采用 [Apache License 2.0](LICENSE)。随包附带的 Cloudflare 资料及适配指导保留 MIT 许可，见 [第三方声明](THIRD_PARTY_NOTICES.md)。
