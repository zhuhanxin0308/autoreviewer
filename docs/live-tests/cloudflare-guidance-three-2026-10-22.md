# Cloudflare 指导接入后三模型实测：2026-10-22

本轮使用三个真实模型，并行启动三个 OpenCode 1.2.27 进程审查 `zhuhanxin0308/clipboard.js`。首轮只有 Super-VL 自动生成有效报告，Lightning 和 Muse 因输出格式失败，整体状态为 `partial`。保持生产提示词和源码不变分别重试后，Muse 自动完成并提出一条候选；Lightning 仍失败。候选经两名独立复核者审查，仍需具体宿主环境验证，本轮采纳的新漏洞为 0，没有新增 Issue。失败记录原样保留，没有人工修复回答或将失败改为空报告。

首轮加两次重试合计三个不同模型、五个 CLI 进程尝试。三个模型均至少有一次真实源码读取；自动有效结构化结果从首轮的 1/3 模型增至含重试后的 2/3 模型，整体完成情况仍为部分完成。不能将这些分别保存的结果描述为一次三模型全部成功的并行扫描，首轮 `partial` 报告也未被改写。

## 目标与方法

- 目标仓库：<https://github.com/zhuhanxin0308/clipboard.js>。
- 本轮使用已准备的固定提交源码：`0c3bce265f6e8bbe6dfd63ec7b01c6e9394c8c93`。每个模型的审计副本包含 25 个文件、41,193 字节；运行前核对副本文件摘要。这个数量是可供审计的快照范围，不是已完成审阅的文件数量。
- 接口：`https://integrate.api.nvidia.com/v1`，协议 `openai-chat`，CLI 为 OpenCode 1.2.27。密钥通过环境变量传递。
- 首轮并发数 3，每个进程超时上限 600 秒，输出上限 8 MiB。单模型重试各使用独立任务和新目录，不覆盖首轮结果。
- 沿用生产 `runner.AUDIT_PROMPT` 以及默认加入的 Cloudflare 指导，没有为测试覆盖提示词、增加输出修复规则或放宽读取权限。
- 观测包装器记录实际 PID、工作目录、HOME、提示词摘要、启动及结束时间和脱敏 CLI 原始事件。事件记录与最终报告分别校验；只有应用自动标为 `completed` 的运行计入有效报告。

模型只静态读取代码，本轮审计轨迹没有运行目标测试、PoC 或写入源码。提示词中的审查方法来自 [只读适配](../audit-guidance.md)，不等于执行上游完整审计及独立验证流程。

## 指导与提示词溯源

三模型首轮和两次重试使用相同的指导与完整提示词：

| 项目 | 记录值 |
| --- | --- |
| 上游 | `https://github.com/cloudflare/security-audit-skill` |
| 固定提交 | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` |
| 模式及适配版本 | `guidance-readonly`，版本 `1` |
| 指导 SHA-256 | `374904b39afb36d65970c7c01ec0425a640ba38a9430b94efe1e08a76ce60cff` |
| 完整提示词 SHA-256 | `14b5d5c856075c4a809935ab61cdf7d0a83520896a5f8a5a2e88e58fd04c97ed` |
| 完整提示词大小 | 12,485 字节 |

已核对构建提示词、实际 CLI 参数、启动时捕获值、保存的提示词文件和报告 `audit_guidance.prompt_sha256` 一致。摘要证明主程序交付了哪些内容，不证明模型遵守了全部规则；是否实际读取源码另以 CLI 顶层工具事件检查。

## 首轮：三个独立进程并行

首轮在 2026-10-22 18:37:08.619–18:44:31.574 UTC 运行，总耗时 442.954 秒。三个 PID 分别为 `30902`、`30903`、`30909`，各自的工作目录和 HOME 不同。依据单调时钟重算，三进程共同重叠 **11.662623 秒**，峰值同时运行三个进程。

这里验证的是本地 CLI 进程并行与目录分离，不能据此证明模型服务端同时推理，也不是操作系统沙箱证明。

| 模型 | 自动状态 | 耗时 | 真实完成的工具调用 | 有效发现 |
| --- | --- | ---: | --- | ---: |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | failed，最终输出格式错误 | 161.967 秒 | 10 次 `read` | — |
| `nvidia/nemotron-3.5-super-vl-120b-a12b` | completed | 442.936 秒 | 9 次 `read` | 0 |
| `meta/muse-glimmer-30b` | failed，最终输出格式错误 | 11.676 秒 | 0 次 | — |

Lightning 实际读取了两个核心源码文件、对应测试文件、README 和包配置，但返回了说明文字与空 `findings` JSON。生产解析器要求完整回答是一个 JSON 文档，因此拒绝该输出，错误为 `agent output is not a complete JSON document`。尾部出现空 JSON 不会把这次运行转为成功。

Super-VL 实际读取了 `src/clipboard.js`、`src/clipboard-action.js`、README 和包配置，最终返回有效的 `{"findings": []}`。这是一份有效的空发现报告，不能解释为目标代码安全或所有文件都已检查。

Muse 首轮仅在文本中写出了类似工具调用的内容，没有 CLI 顶层 `tool_use` 记录，也没有真实源码读取证据；它不能算作已经完成代码审计。三进程退出码均为 0，但两次回答未通过应用层校验，说明 CLI 正常退出不等于报告有效。

工具计数来自去重后的真实 CLI 事件。`read` 也包含目录读取或重复读取，不能将调用次数当作独立源码文件数或覆盖率。

## 原样重试

两个失败模型各重试一次，使用相同模型 ID、源码、生产提示词、权限和 600 秒超时。重试在首轮其他模型仍运行时独立启动；每个重试任务自身并发数为 1，因此不能将它们描述为与其他调用完全隔离的性能测试。

| 模型 | 自动状态 | 耗时 | 真实完成的工具调用 | 有效发现 |
| --- | --- | ---: | --- | ---: |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | failed，最终输出格式错误 | 128.181 秒 | 15 次 `read`、2 次 `glob` | — |
| `meta/muse-glimmer-30b` | completed | 359.477 秒 | 11 次 `read`、1 次 `glob`、2 次 `grep` | 1 条 `unverified` 候选 |

Lightning 重试读取了两个核心源码文件、测试文件、包配置及六个 demo 文件，但回答仍附带说明文字，未通过同一 JSON 校验。没有抽取尾部 JSON 或人工重写后计为成功。

Muse 重试有真实读取两个核心源码文件及测试、文档的证据，并自动输出有效发现 JSON。它提出 `src/clipboard.js:75` 的候选：页面若将低信任内容中的 `data-clipboard-target` 接入触发元素，CSS 选择器可能指向页面其他内容并触发复制。模型给出的 `medium` 严重程度和 `CWE-200` 仍是未经确认的判断；结构校验成功只说明报告格式有效。

## Muse 候选的独立复核

两名独立复核者均给出 `needs_host_validation`，未采纳为 `clipboard.js` 本身已成立的新漏洞。这个结论单独保存在复核记录中；模型原始候选及 `unverified` 状态保留，不篡改自动报告，也不宣称相关集成绝对没有风险。

候选引用的选择器到 DOM 文本、剪贴板操作和实例事件的源码路径真实存在，但文档同时明确了调用约定：

- `readme.md:34–42`：开发者选择并绑定 trigger，库不会自动激活任意页面节点。
- `readme.md:50–61`：`data-clipboard-target` 的设计用途就是用 CSS 选择器指定复制目标。
- `readme.md:101–110`：结果事件包含 `e.text` 是公开功能。
- `readme.md:134–141`：开发者可以用 `target(trigger)` 回调返回明确的目标元素。

当前仓库未给出低信任 HTML 的实际输入入口、清洗后保留相关属性的规则、应受限制却被绕过的授权边界，以及攻击者取得复制内容的出口。将内容写入受害者自己的剪贴板，或发送给应用内部事件监听器，不等于攻击者已经获得内容。模型提出的无效选择器异常处理建议也不能证明该信息泄露结论。

若要确认具体宿主应用存在风险，需要补充真实输入、绑定、权限与内容接收路径的证据。因此本轮新增采纳漏洞为 0，不为这条候选发布 Issue。结束时核对 GitHub：此前的 #6–#9 仍为 open，仓库已有 9 条 Issue 的标题、正文及状态与本轮开始前一致。

## 与既有问题的关系及限制

此前五模型审查使用了包含功能缺陷的任务范围，本轮沿用生产安全审查提示词，侧重可达攻击者、信任边界和安全影响。两轮提示词范围不同，不能通过发现数量变化评估 Cloudflare 指导的效果。此前已复核的资源清理和空字符串反馈等功能问题，也不会被本轮空报告或失败回答推翻。

当前证据不证明目标没有漏洞、审查覆盖完整，或指导提高了检出率、降低了误报率。工具读取只证明相应内容返回给模型，不证明模型充分推理了所有路径、宿主页面信任边界及依赖实现。失败模型仍算失败，不按空发现计入“通过”；模型输出、人工复核与实际发布必须分别记录。

不同重试的结果表明同一模型组合仍可能有工具调用或格式稳定性问题。单次耗时受调用过程和平台负载影响，不是性能排名。本轮也不验证平台免费额度、价格或长期可用性。

结束后确认各次尝试的临时工作目录和 HOME 均已删除，输入源码目录的 27 个文件摘要前后未变。保留的诊断文件经 NVIDIA `nvapi-` 密钥格式扫描未发现匹配；这项检查仅说明该格式扫描结果，不是所有敏感内容均已排除的证明。

## 复现配置

安装 OpenCode，在环境中设置 `NVIDIA_API_KEY`，将以下配置保存到本地文件，然后使用同一目标提交扫描：

```toml
version = 1

[scan]
concurrency = 3
timeout_seconds = 600
max_output_bytes = 8388608

[providers.nvidia]
base_url = "https://integrate.api.nvidia.com/v1"
api_key_env = "NVIDIA_API_KEY"
api_format = "openai-chat"

[[models]]
id = "nemotron-lightning"
provider = "nvidia"
model = "nvidia/nemotron-3.5-lightning-30b-a3b"
agent = "opencode"

[[models]]
id = "nemotron-super-vl"
provider = "nvidia"
model = "nvidia/nemotron-3.5-super-vl-120b-a12b"
agent = "opencode"

[[models]]
id = "muse-glimmer"
provider = "nvidia"
model = "meta/muse-glimmer-30b"
agent = "opencode"
```

```bash
autoreviewer scan https://github.com/zhuhanxin0308/clipboard.js \
  --ref 0c3bce265f6e8bbe6dfd63ec7b01c6e9394c8c93 \
  --config ./guided-three.toml --output ./guided-three-result
```

复现需使用记录中的 CLI、autoreviewer 指导版本及提示词摘要；新版本提示词或平台变化可能导致不同结果。这个命令运行产品扫描，不会生成下面测试包装器专有的进程与原始事件观测文件，也不会自动发布 Issue。

## 原始记录

本次工作区证据位于 `/workspace/work/clipboard-guided-three-review/`：

- `source-manifest.json`、`source-hashes.json`：固定提交与准备好的源码文件摘要。
- `three-model-result/`：首轮报告、各模型终态记录、提示词文件、实际进程记录和脱敏 CLI 事件。
- `lightning-retry-result/`、`muse-retry-result/`：各次独立重试的同类记录。
- `initial-validation.json`、`lightning-retry-validation.json`、`muse-retry-validation.json`：提示词交付、运行状态、真实工具事件及并发证据核对结果。
- `verification-baseline.json`：既有功能缺陷、已发布问题及排除项的历史复核基线，不表示本轮重新确认了远端 Issue 状态。
- `model-review-verification.json`：独立复核已记录的模型输出与证据；与生产报告的自动状态分开保存。
- `muse-independent-review.json`：Muse 候选的源码路径、公开调用约定、尚缺的宿主事实及不发布判定。
- `cleanup-verification.json`：临时目录清理与 NVIDIA 密钥格式扫描结果。

以上本地证据路径用于本次工作区溯源，不随本文链接自动公开原始源码或日志。
