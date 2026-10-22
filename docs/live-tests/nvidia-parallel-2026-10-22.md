# NVIDIA 五并发与八并发实测：2026-10-22

本次实际启动了五个、随后八个独立的 OpenCode 1.2.27 进程，每个进程使用不同模型和独立代码副本。五并发批次有两个模型完成；八并发批次有五个模型完成。两份报告的整体状态均为 `partial`，失败结果保留，不将接口探测通过视为审计完成。

## 范围与方法

- NVIDIA 接口：`https://integrate.api.nvidia.com/v1`，`openai-chat`。
- 两批次使用同一个 41 行、1,717 字节的人工构造样例：[app.py](../../examples/audit-fixture/app.py)。
- 样例 SHA-256：`9460bc205d4e9d0731b9ee8c2354bee47b841e8bf94f053495823d30eb58138c`。
- [预期结果](../../examples/audit-fixture-expected.json)位于扫描目录之外：`app.py:6` 的 SQL 注入、`app.py:12` 的路径遍历；`app.py:16–19` 是安全参数化查询对照。
- 每个进程超时上限 300 秒，沿用正常产品提示词、工具权限和模型输出校验。测试包装器仅记录进程时序及脱敏诊断，不修改模型回答。
- 用实际进程 PID、启动及退出的单调时钟时间记录并发。这里测量的是本地 CLI 进程重叠，不是 NVIDIA 服务端同时推理的数量。
- 密钥通过环境传递；没有写入配置或报告，也没有发布 GitHub Issue。

## 第一批：五并发

运行时间为 17:49:17.918–17:50:18.222，Asia/Shanghai（UTC+8）；测量总耗时 60.307 秒。五个不同 PID 的启动记录间隔为 0.001567 秒，峰值同时运行五个进程，五进程共同重叠约 2.481 秒。

| 模型 | 状态 | 运行耗时 | 有效发现 |
| --- | --- | ---: | ---: |
| `openai/gpt-oss-20b` | completed | 30.293 秒 | 2 |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | completed | 60.299 秒 | 2 |
| `nvidia/nemotron-nano-3-30b-a3b` | failed，HTTP 404 | 2.818 秒 | — |
| `nvidia/nemotron-3-super-120b-a12b` | failed，HTTP 404 | 2.618 秒 | — |
| `moonshotai/kimi-k2.6` | failed，HTTP 404 | 2.488 秒 | — |

三个 404 的服务端诊断均表示当前账号找不到对应模型服务。目录中存在模型条目不能保证实际可调用。两个成功模型都定位了两处预置问题，未将安全查询对照列为 SQL 注入。聚合报告保留四条记录，对应两个根因。

## 候选筛选

在第二批之前，对八个其他候选各进行了一次最多 512 输出 token、25 秒超时的工具调用探测，没有发送源码或执行工具。

`nvidia/nemotron-3.5-super-vl-120b-a12b`、`nvidia/nemotron-3-ultra-550b-a55b`、`stepfun-ai/step-5-preview`、`meta/muse-glimmer-30b`、`z-ai/glm-5.3`、`google/diffusiongemma-26b-a4b-it` 返回 HTTP 200 和有效工具调用，进入第二批。`poolside/laguna-xs-2.1` 返回 HTTP 503；`google/gemma-4-31b-it` 超时，未进入第二批。

## 第二批：八并发

运行时间为 17:55:25.956–18:00:26.095，Asia/Shanghai（UTC+8）；测量总耗时 300.143 秒。八个不同 PID 的启动记录间隔为 0.004426 秒，八进程共同重叠 5.298632 秒。同一批次中最终完成的五个进程共同重叠 12.779074 秒。

| 模型 | 状态 | 运行耗时 | 有效发现 |
| --- | --- | ---: | ---: |
| `openai/gpt-oss-20b` | failed，输出事件流无效 | 214.720 秒 | — |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | completed | 28.934 秒 | 2 |
| `nvidia/nemotron-3.5-super-vl-120b-a12b` | completed | 17.118 秒 | 2 |
| `nvidia/nemotron-3-ultra-550b-a55b` | completed | 12.806 秒 | 2 |
| `stepfun-ai/step-5-preview` | completed | 116.791 秒 | 2 |
| `meta/muse-glimmer-30b` | completed | 44.810 秒 | 2 |
| `z-ai/glm-5.3` | timeout | 300.124 秒 | — |
| `google/diffusiongemma-26b-a4b-it` | failed，HTTP 400 | 5.316 秒 | — |

GPT-OSS 本轮反复产生无效工具调用，OpenCode 又向 stdout 输出了非 JSON 的 schema 校验堆栈，没有形成有效的最终审计结果。该模型在前面的批次成功过，本轮仍按失败记录，不能据此归因于单一的并发或模型因素。

DiffusionGemma 的首次简单工具调用探测成功，但实际 agent 在后续回传消息时被服务端拒绝：`Empty content is not allowed for assistant messages`。这说明完整的多轮工具协议兼容性还需要单独验证。

GLM 5.3 达到配置的超时上限后进程被终止；超时不代表没有漏洞。无效输出与超时都没有被转换为正常空结果。

## 结果复核与限制

第二批五个完成模型各报告两个预置根因，文件与行号符合样例；安全参数化查询没有被列为漏洞。共十条模型发现对应两个预置问题，并非十个独立漏洞。由于标题措辞不同，当前保守去重规则仍保留十条记录，后续需要语义分组或人工复核。

已逐条人工复核十条发现，并在独立评估文件保留每条意见。Super-VL 将 `commonprefix` 作为路径校验备选方案，这种字符串前缀校验不能保证目录边界；应采用解析路径后的 `Path.is_relative_to` 或 `os.path.commonpath`，并明确符号链接和竞态策略。其 SQL 报告声称可能修改数据库，但样例的单条 `SELECT` 和 `sqlite3.execute` 不足以支持此结论。Lightning 的一处源码引用不完全准确；Step 的 HTTP 500 推断缺少外层服务器与异常处理证据。定位根因正确不代表所有描述和修复建议正确。

此测试没有执行漏洞利用，不验证部署严重程度或所有修复方案，原始发现仍保持未验证状态。

本次只验证一个小样例的进程调度、真实 API 和 CLI 工具调用、输出校验与结果汇总，不是准确率、性能或稳定性基准。不同模型的请求量、服务负载和输出长度不同，不能根据单次耗时制作可靠排名。没有验证免费额度、计费规则或长期模型可用性。

## 本次代码修正

首次批次暴露了错误信息过于笼统的问题。OpenCode 适配器现在对结构化 API 错误显示 HTTP 状态和固定分类说明，例如 `HTTP 404: model or endpoint unavailable`。不会直接传播服务端原始响应体、响应头或账号标识。增加分类、异常类型和敏感信息排除测试后，全部 96 项自动化测试通过。

## 复现与原始记录

[八模型配置](../../examples/nvidia-parallel.toml)用于复现本次模型池，包含观察到失败的组合，不是所有条目都已稳定可用的推荐配置。先安装 OpenCode 并在环境中设置 `NVIDIA_API_KEY`，再执行：

```bash
autoreviewer scan examples/audit-fixture \
  --config examples/nvidia-parallel.toml \
  --output ./nvidia-parallel-result
```

原始记录在本次工作区中分别保留：

- `/workspace/work/autoreviewer-live/parallel-five/`：第一批 JSON 与 Markdown 报告。
- `/workspace/work/autoreviewer-live/parallel-eight/`：第二批 JSON 与 Markdown 报告。
- 同级 `parallel-five-processes.json`、`parallel-eight-processes.json`：实际进程时序。
- 同级 `parallel-five-evaluation.json`、`parallel-eight-evaluation.json`：按样例预期独立复核的结果。
- 同级 `parallel-candidate-probes.json`：小请求探测结果，与完整审计记录分开保存。

[此前两模型与单独重试的记录](nvidia-2026-10-22.md)仍保留，不用新批次覆盖旧失败或成功。
