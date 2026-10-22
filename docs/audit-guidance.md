# 审计指导集成

autoreviewer 默认将 [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) 的审查方法适配到统一提示词，用于指导各模型阅读代码、提出并反驳候选问题。无需新增配置，也无需运行 `npx` 或向本机 agent CLI 安装 skill；扫描期间不下载上游内容。

## 来源与文件布局

当前固定上游提交 [`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8)，采用 MIT 许可，版权归 Cloudflare, Inc.。随包附带：

| 路径 | 用途 |
| --- | --- |
| `src/autoreviewer/audit_guidance/cloudflare/upstream/` | 该提交的原始资料快照，保留上游文件及许可 |
| `src/autoreviewer/audit_guidance/cloudflare/GUIDANCE.md` | 适合 autoreviewer 只读审计的指导文本，实际进入提示词 |
| `src/autoreviewer/audit_guidance/cloudflare/manifest.json` | 来源、固定提交、适配版本与资源摘要 |
| `src/autoreviewer/guidance.py` | 从包内资源加载指导并生成来源元数据 |

原始快照用于溯源与维护，并非将所有上游文档逐字加入每个提示词。上游的 `.cjs` 校验器及其测试保留作参考，autoreviewer 不执行它们，也不因此增加 Node.js 运行依赖。许可全文见 [上游 LICENSE](../src/autoreviewer/audit_guidance/cloudflare/upstream/LICENSE)，第三方归属见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

## 如何使用

现有 Web 界面和 `autoreviewer scan` 命令自动使用指导，模型与平台配置方式不变。OpenCode、Codex CLI、Claude Code 和 Gemini CLI 均通过主程序构造的提示词接收它。

自定义 CLI 的 `{prompt}` 参数与 `AUTOREVIEWER_AUDIT_PROMPT` 环境变量提供相同的完整提示词，包含指导、任务要求及 autoreviewer 输出格式。包装程序负责将其中一种传给模型；仅配置自定义命令不会使包装程序自动遵守提示词。

指导从 autoreviewer 安装包加载，不从待审计仓库加载。原有项目配置过滤与原生 skill 自动加载限制保持不变，避免目标仓库中的指令文件替换审查规则。它不会改变各实例的独立代码副本、HOME、超时和并发设置。

## 只读适配范围

适配模式为 `guidance-readonly`。模型应执行以下静态审查步骤：

1. 识别攻击者可控输入、信任边界、受影响主体及资源。
2. 从实际入口追踪到危险操作，检查完整的数据流、控制流和必要条件。
3. 查找现有校验、权限检查、编码和隔离机制，主动尝试推翻候选问题。
4. 排除无效配置、纯粹的加固建议和缺乏可达路径的猜测。
5. 给出真实源码文件、行号、相关证据及最小有效修复建议。

这并未实现上游完整的六阶段审计编排、覆盖台账或独立验证器。现有只读约束仍然有效，不允许运行目标程序、PoC 或项目测试，也不授予修改目标文件的权限。模型可以使用读取、搜索和列目录工具；仅通过 shell 提供读取能力的 CLI 可使用已安装的只读文本查看和搜索工具，不得解释或执行仓库内容。自定义 CLI 的权限仍由受信任的包装程序负责；提示词与 CLI 只读限制不构成操作系统沙箱。

报告继续使用 [autoreviewer 发现格式](architecture.md#发现的数据约定)，不改为上游报告 schema。所有发现的 `verification` 仍为 `unverified`，多模型一致也不会自动确认漏洞。上游完整流程只对已确认问题给出严重程度；本项目中的 `severity` 保留为模型对潜在影响的暂定评估，不能解释为已完成上游验证。`confidence` 同样不是复现结论。

接入指导不代表模型必然遵守，或每个文件都已覆盖；目前没有实测证明它提高了检出率或降低了误报率。早期 NVIDIA 并发记录发生在本次指导集成之前，不能作为指导效果的验证。接入后的[三模型真实并发记录](live-tests/cloudflare-guidance-three-2026-10-22.md)确认了提示词交付与进程隔离，含重试后两个模型取得有效结构化报告，另一个仍格式失败；这次结果也不能用作检出率或误报率的对比实验。

## 报告中的来源记录

每个模型运行的 `audit_guidance` 包含：

| 字段 | 含义 |
| --- | --- |
| `id` | `cloudflare-security-audit` |
| `source` | `https://github.com/cloudflare/security-audit-skill` |
| `commit` | 固定的上游提交 SHA |
| `mode` | `guidance-readonly` |
| `adaptation_version` | autoreviewer 适配文本版本 |
| `guidance_sha256` | 适配指导文本的 SHA-256 摘要 |
| `prompt_sha256` | 本次完整审计提示词的 SHA-256 摘要 |

这些记录随模型运行保存在检查点和最终报告中，便于比较不同批次实际配置的指导。旧报告没有该字段时保持缺省，不会补写当前版本或宣称旧扫描使用了新指导。导入保留已有元数据，结构校验不证明来源真实性。

摘要记录主程序配置和交付的内容，不证明自定义包装程序将提示词传给了模型，也不证明模型执行了所有审查步骤。摘要不是漏洞确认或审计覆盖证明。

## 升级指导

上游更新不会自动进入现有安装。维护者升级时应：

1. 选择并固定新的完整提交 SHA，审阅上游变更及许可，更新原始快照。
2. 人工审阅 `GUIDANCE.md` 的适配，保留只读权限、待验证状态和现有输出约定；不要直接复制要求执行 PoC 或开启工具权限的流程。
3. 更新 `manifest.json` 中的来源版本、资源摘要，以及适配文本变更对应的 `adaptation_version`；同步本文与第三方声明。
4. 运行 `python -m unittest discover -s tests -v`，确认提示词注入、来源记录及旧报告兼容性；构建并检查发行包包含指导、原始快照和许可证，再验证安装后的资源加载。

若要支持完整上游流程，需要另外设计执行隔离、验证状态、覆盖记录和独立验证器，不能仅通过替换提示词宣称已实现。
