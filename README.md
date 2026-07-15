# 化工环评工程分析技能包

> 中文说明在前，英文说明保留在本文后半部分。This README continues in English below.

## 这是做什么的

这是一个面向化工环评技术人员的工程分析基础工作台，由一个可安装到 Codex 的 Skill 和一套确定性 Python 程序组成。

它把化工生产过程统一表达为“节点和流股”：反应、混合、分流、回流、蒸馏、治理设施等都按照“输入 → 操作 → 输出”组织。AI 负责把技术资料翻译成结构化工序模型，程序负责计算、校验和生成结果，技术员保留最终专业判断权。

**v0.1.0 Preview 是化工环评工程分析的基础工作台和确定性管线，不是“上传可研报告即可自动完成完整工程分析”的成品系统。**

## v0.1.0 Preview 现在能做什么

当前版本主要用于验证以下工作流程：

- 引导 AI 从本次提供的资料中提取工序、设备、输入、输出、物料去向和可能的产污节点；
- 完成结构化工序建模，建立支持串联、分流、合流、旁路和回流的工序模型；
- 保存资料来源，区分企业明确事实、AI 暂定建议和技术员确认结果；
- 对输入条件完整的反应工序进行确定性物料衡算；
- 检查节点连接、流股引用、物料闭合、参数缺失、来源缺失和未经采纳的 AI 建议；
- 输出工艺模型、流程图、衡算诊断和技术员审核报告；
- 通过独立的技术员决定文件，演示从 `preliminary` 到 `formal` 的确认闭环。

当前程序不会让 AI 靠心算替代确定性计算，也不会把 AI 建议自动变成企业确认数据。

## 当前还不能做什么

当前版本**不能保证**完成下面这条全自动流程：

```text
原始可研报告
→ 自动识别全部工艺和设备
→ 自动补齐全部缺失数据
→ 自动完成全流程物料衡算
→ 自动完成废气、废水、固废和水平衡
→ 自动生成可直接交付的完整工程分析报告
```

仍需继续开发的内容包括：

- 完整的 `.doc`、`.docx`、PDF、表格和图片流程图读取；
- 蒸馏、精馏、萃取、过滤、干燥、储罐、真空系统、RTO、污水处理等全部非反应工序计算；
- 全流程溶剂循环、母液回用、多级回流和逐组分闭合；
- 完整废气源强、废水和水平衡、固废源强核算；
- 工序—设备—产污完整对照表和工程分析报告章节自动生成。

因此，当前版本适合受控测试、流程验证和技术员辅助分析，不适合无人值守地作出合规结论。

## 下载与安装

### 下载已经发布的预览版

打开 GitHub 仓库页面右侧的 **Releases**，进入 `v0.1.0`，可以看到：

```text
analyzing-chemical-eia-processes-0.1.0.zip
chemical_eia_core-0.1.0-py3-none-any.whl
chemical_eia_core-0.1.0.tar.gz
SHA256SUMS.txt
```

其中：

- `analyzing-chemical-eia-processes-0.1.0.zip` 是给 Codex 使用的 Skill 压缩包；
- `.whl` 是 Python 安装包；
- `.tar.gz` 是 Python 源码安装包；
- `SHA256SUMS.txt` 用于核对下载文件有没有被修改。

### 安装到 Codex

1. 下载并解压 `analyzing-chemical-eia-processes-0.1.0.zip`；
2. 保持目录名为 `analyzing-chemical-eia-processes`；
3. 把该目录复制到当前 Codex 环境的 `skills/` 目录；
4. 重启或重新载入 Codex 会话；
5. 通过 `$analyzing-chemical-eia-processes` 调用。

如果直接使用仓库源码，可以在仓库根目录运行：

```text
python -c "from pathlib import Path; import shutil; shutil.copytree(Path('skills/analyzing-chemical-eia-processes'), Path('.codex/skills/analyzing-chemical-eia-processes'), dirs_exist_ok=True)"
```

### 安装 Python 核心

从 Releases 下载 Wheel 后，在文件所在目录运行：

```text
python -m venv .venv
python -m pip install chemical_eia_core-0.1.0-py3-none-any.whl
python -m chemical_eia.cli --help
```

也可以在仓库根目录安装：

```text
python -m venv .venv
python -m pip install .
chemical-eia --help
```

运行时没有第三方 Python 依赖；从源码构建 Wheel 或 sdist 时，需要 `pyproject.toml` 中声明的构建工具。

## 五分钟运行示例

仓库中的 `examples/minimal` 是完全虚构的演示数据，不包含真实企业资料。

第一次不提供技术员决定：

```text
chemical-eia examples/minimal/model.json --output-dir examples/minimal/output-preliminary
```

第二次加入已经审核的决定文件：

```text
chemical-eia examples/minimal/model.json --decisions examples/minimal/decisions.json --output-dir examples/minimal/output-formal
```

对比两次生成的 `review-report.md` 和 `project-model.yaml`，可以看到结果从 `preliminary` 转换为 `formal`。

## 会生成哪些文件

程序固定生成四类成果：

1. `project-model.yaml`：结构化工序、节点、流股、参数、来源、计算结果和问题清单；
2. `process-flow.mmd`：用于检查工艺连接关系的 Mermaid 流程图；
3. `diagnostic-balance.yaml`：物料衡算和模型诊断结果；
4. `review-report.md`：阻塞问题、待核实问题、AI 暂定建议和技术员待办。

这些文件是工程分析输入和审核材料。文件成功生成，不代表原始资料已经完整，也不代表结果已经被企业或技术员接受。

## preliminary 和 formal 的区别

- `preliminary`：模型中仍有 AI 暂定建议、待核实参数或尚未完成的技术员决定；
- `formal`：当前模型中影响状态的建议已经通过独立决定文件被技术员采纳、修改或拒绝，并且阻塞性校验问题已经解决。

**`formal` 只表示当前模型中已支持的内容经过规定的技术员确认，不表示整份环评工程分析报告已经完整完成。** 企业确认和技术人员的最终专业判断仍然不可替代。

## 谁负责什么

| 参与方 | 主要职责 | 不能做什么 |
|---|---|---|
| AI | 阅读资料、提取事实、建立结构化草稿、提出有来源和状态标记的建议 | 不能把推测伪装成企业事实，不能替技术员确认 |
| 确定性程序 | 查表、计算、校验、诊断、生成结构化成果 | 不能凭空补齐未披露的反应和物料去向 |
| 技术员 | 核实资料、判断方法、采纳或拒绝建议、处理冲突、作出最终专业决定 | 不能把未经核实的自动结果直接当成企业确认数据 |
| 企业 | 提供和确认真实工艺、设备、参数、运行条件及物料去向 | 企业确认不能由软件自动替代 |

## 支持环境

| 项目 | v0.1.0 支持情况 |
|---|---|
| 操作系统 | Windows、Ubuntu |
| Python | 3.10、3.11、3.12、3.13 |
| Python 发布格式 | Wheel、sdist |
| Agent 入口 | Codex Canonical Skill |
| 适配器 | Claude Code manifest |
| 数据格式 | JSON 或 YAML 工序模型和技术员决定文件 |

## 安全和使用边界

- 项目数据不应写入 Skill 本身，换项目时只更换输入资料；
- 不要在公开 Issue、测试案例或提交记录中上传未经授权的企业报告、个人信息、账号凭据和令牌；
- 真实资料应保留来源锚点、版本和冲突，不要为了得到“完整答案”而隐藏资料缺口；
- 漏洞报告请阅读 `SECURITY.md`；开发要求请阅读 `CONTRIBUTING.md`；使用边界请阅读 `SUPPORT.md`；
- 项目采用 Apache-2.0 许可证，完整条款见 `LICENSE`。

## English documentation

---
# Chemical EIA Process Analysis

Chemical EIA Process Analysis is a portable skill pack and deterministic Python core for structuring chemical-process engineering analysis. It turns technician-reviewed process models into traceable tables and diagnostic calculations while keeping professional judgment with the technician.

## Preview status

This v0.1.0 release is a Preview. It is intended for controlled evaluation, reproducible workflow testing, and technician-assisted drafting. It is not a regulatory conclusion, does not replace enterprise verification, and must not be used as an unattended compliance decision system.

## Install the Python package

From the repository root, create an isolated environment and install the local package:

```text
python -m venv .venv
python -m pip install .
chemical-eia --help
```

The runtime has no third-party Python dependencies. Building a wheel or sdist requires the build tools declared in `pyproject.toml`.

## Install the Canonical Skill in Codex

The canonical Skill is stored at `skills/analyzing-chemical-eia-processes/`. Copy that directory into the `skills/` directory of the Codex home you are using. Keep the directory name unchanged so `$analyzing-chemical-eia-processes` remains the invocation name.

For a repository-local evaluation layout, use relative paths:

```text
python -c "from pathlib import Path; import shutil; shutil.copytree(Path('skills/analyzing-chemical-eia-processes'), Path('.codex/skills/analyzing-chemical-eia-processes'), dirs_exist_ok=True)"
```

Restart or reload the Codex session after installation.

## Install the Claude Code adapter

The adapter manifest at `adapters/claude-code/adapter.json` points to the canonical Skill and its relative installation target. Install the same Skill content rather than maintaining a second prompt:

```text
python -c "from pathlib import Path; import shutil; target=Path('.claude/skills/analyzing-chemical-eia-processes/SKILL.md'); target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(Path('skills/analyzing-chemical-eia-processes/SKILL.md'), target)"
```

## Five-minute minimal example

The `examples/minimal` dataset is completely fictional. Run it first without technician decisions:

```text
chemical-eia examples/minimal/model.json --output-dir examples/minimal/output-preliminary
```

Then rerun with the reviewed decision record:

```text
chemical-eia examples/minimal/model.json --decisions examples/minimal/decisions.json --output-dir examples/minimal/output-formal
```

Compare the review reports and model outputs. The first run demonstrates a `preliminary` state; the second demonstrates the transition that is permitted only after a technician decision is supplied.

## Four outputs

The CLI writes four traceable artifacts:

1. `project-model.yaml` preserves the structured process model used for process-equipment-waste correspondence.
2. `process-flow.mmd` renders the node-and-stream view used to review routing and material balance context.
3. `diagnostic-balance.yaml` contains deterministic diagnostic calculations that support material balance, three-waste source strength, and water balance review.
4. `review-report.md` lists unresolved assumptions, conflicts, adoption status, and blocking items for technician action.

These artifacts are engineering-analysis inputs. Their presence does not mean that source data are complete or that a result has been accepted.

## From preliminary to formal

AI-proposed values remain `preliminary` and carry provenance, basis, version, and review status. The deterministic program may calculate with an explicitly permitted provisional candidate, but it cannot adopt that candidate.

A result becomes `formal` only when a technician records an explicit decision in a separate decisions file, the pipeline applies that decision without erasing history, and all blocking validation findings are resolved. Enterprise confirmation may still be required. Software never substitutes for that confirmation authority.

## Architecture boundary

The Skill translates submitted material into a structured node-and-stream model. The Python core performs routing, validation, arithmetic, balance diagnostics, and rendering. It does not infer undisclosed reaction definitions, silently repair missing flows, or convert an AI suggestion into a technician decision.

Project data stay outside the Skill. Use fictional or properly authorized inputs, preserve source anchors, and keep review decisions separate from the raw model.

## Support matrix

| Component | Supported in v0.1.0 |
|---|---|
| Operating systems | Windows and Ubuntu |
| Python | 3.10, 3.11, 3.12, 3.13 |
| Python package | wheel and sdist |
| Agent entry | Canonical Codex Skill |
| Adapter | Claude Code manifest |
| Data format | JSON or YAML process model and decisions |

## Security, contributing, and license

Read `SECURITY.md` before reporting a vulnerability and never attach confidential project material or credentials. Development and fictional-test-data requirements are in `CONTRIBUTING.md`; usage boundaries are in `SUPPORT.md`; release changes are in `CHANGELOG.md` and `docs/release-notes/v0.1.0.md`.

The project is licensed under Apache-2.0. See `LICENSE` for the complete terms.
