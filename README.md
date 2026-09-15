# Decompiling Binary Code with Large Language Models

这是一个使用 Ghidra、静态规则和大语言模型辅助恢复二进制程序 C 代码的工具链项目。项目不仅可以批量反编译二进制文件，还能把 Ghidra 生成的伪 C 代码整理为可编译工程，并围绕 GCC 编译错误持续修复函数签名、参数数量、变量声明和内部类型。

## 已实现能力

- 使用 PyGhidra 无界面反编译单个文件、目录或通配符匹配的多个二进制文件。
- 支持并行处理、断点续跑、超时、指定函数、单文件输出和元数据导出。
- 将按函数拆分的 Ghidra 伪 C 代码补齐为包含头文件、全局数据和构建脚本的工程。
- 通过确定性规则或 LLM 执行“编译—分析错误—生成补丁—重新编译”的静态修复闭环。
- 根据调用点修正函数参数数量，根据符号表补齐未声明符号。
- 根据伪代码、汇编和调用关系推断函数签名及函数体内部类型。
- 提供 PySide6 桌面界面，以及单元、黄金回归和端到端测试。

> 本项目的收敛标准主要是“生成代码可以编译”。能够编译不等同于与原二进制运行行为完全一致；复杂类型、跳转表、静态链接运行库和被优化掉的语义仍可能需要人工分析与动态验证。

## 文件夹分类原则

```text
.
├── plugins/   项目实现：核心模块、CLI、GUI、配置示例和使用说明
├── tests/     项目验证：测试代码、固定样本、错误资料和实验结果
├── ignore/    本地内容：第三方工具、虚拟环境、生成物、配置和私有资料
├── README.md  项目总览与入口文档
└── .gitignore Git 忽略规则
```

分类遵循以下原则：

- 能构成项目功能、需要协作维护的实现代码和公开说明放入 `plugins/`。
- 用于验证功能或记录实验表现的测试代码、输入样本和结果放入 `tests/`。
- 可重新安装或重新生成、与具体电脑有关、包含个人信息或不应公开的内容放入 `ignore/`。
- `ignore/` 整体不进入 Git；当前细分为 `tools/`、`envs/`、`generated/`、`local/` 和 `private/`。
- `.agents/`、`.codex/` 是工作环境挂载点，无法移动，因此留在根目录并由 `.gitignore` 忽略。

## 环境要求

### 基础功能

- 建议 Python 3.11 或 3.12（与所安装 PyGhidra、PySide6 版本匹配）
- Ghidra，以及与该版本 Ghidra 兼容的 Java
- PyGhidra（运行 `decompile_binary.py` 和签名回灌功能时需要）
- GCC 与 Make（生成工程后编译及错误驱动修复时需要）
- Windows 上的编译流程默认通过 WSL 调用 `make`

只使用 `decompile_helper.py` 生成工程时仅需 Python 标准库；它自身不启动 Ghidra。编译与 LLM 证据提取分别需要上面的额外工具。以下完整编译示例以 Linux/WSL、匹配架构的 ELF 输入为主；PE 输入的重建还受目标平台和编译器限制。

### 可选功能

- PySide6：运行桌面 GUI
- pytest：运行自动测试
- PyYAML：使用 `decompile_binary.py --config` 读取 YAML 配置时需要；JSON 配置无需此依赖
- OpenAI Chat Completions 兼容接口：运行 LLM 修复功能；默认配置面向 DeepSeek

本地依赖推荐采用如下布局：

```text
ignore/
├── tools/ghidra12.1/
└── envs/pyghidra_env/
```

项目会自动尝试查找 `ignore/tools/ghidra12.1`。也可以显式指定：

```bash
export GHIDRA_INSTALL_DIR="$PWD/ignore/tools/ghidra12.1"
```

如果 PyGhidra 安装在项目的本地虚拟环境中，可直接使用该解释器：

```bash
ignore/envs/pyghidra_env/bin/python plugins/decompile_binary.py --help
```

在新环境中，应自行创建虚拟环境，并按照所用 Ghidra 版本的说明安装 PyGhidra。GUI 和测试依赖可按需安装：

```bash
python -m pip install PySide6 pytest
```

## 快速开始

以下命令都从仓库根目录执行。`sample.exe` 和 `./binaries` 是占位路径，请换成真实输入；扩展名不决定其实际二进制格式。`python` 必须指向安装了所需依赖的解释器，例如将它替换为 `ignore/envs/pyghidra_env/bin/python`。示例把运行结果写入 `ignore/generated/`，避免误提交生成物。

### 1. 反编译二进制文件

```bash
python plugins/decompile_binary.py sample.exe \
  -o ignore/generated/decomp_out
```

常见用法：

```bash
# 递归处理目录，并使用 4 个工作进程
python plugins/decompile_binary.py ./binaries \
  -o ignore/generated/decomp_out --recursive --parallel 4

# 只反编译指定名称或地址的函数
python plugins/decompile_binary.py sample.exe \
  -o ignore/generated/decomp_out --functions main 0x401000

# 只列出函数，不输出反编译代码
python plugins/decompile_binary.py sample.exe --list-functions

# 预览将处理哪些输入文件
python plugins/decompile_binary.py ./binaries --recursive --dry-run
```

默认情况下，每个输入文件会在输出目录下形成 `<文件名>_decomp/`，其中通常按函数保存 `.c` 文件。详细参数见 `plugins/decompile_binary_usage.txt` 或：

```bash
python plugins/decompile_binary.py --help
```

其他常用参数：

| 参数 | 用途 |
| --- | --- |
| `--single-file -O <file.c>` | 合并输出到指定 C 文件；后续工程生成流程使用按函数拆分的输出 |
| `--resume <state.json>` | 使用状态文件续跑，建议把状态放入 `ignore/generated/` |
| `--timeout <秒>`、`--max-memory 4G` | 限制处理时间、JVM 堆内存 |
| `--meta`、`--mirror` | 导出元数据、保留输入目录层次 |
| `--config <json或yaml>`、`--log-file <文件>` | 加载选项配置、写入日志 |
| `--ghidra-dir <目录>`、`--project-dir <目录>` | 指定 Ghidra 安装和项目数据库位置 |
| `--lang <ID>`、`--compiler <ID>` | 显式指定目标语言和编译器规格 |
| `--overwrite` | 允许覆盖已有输出 |

仅指定 `-o` 不会改变 Ghidra 项目数据库位置。需要集中存放时另外传入 `--project-dir ignore/generated/ghidra_projects`；默认命名的输入旁数据库也已加入忽略规则。

### 2. 生成可编译工程

```bash
python plugins/decompile_helper.py all \
  sample.exe \
  ignore/generated/decomp_out/sample_decomp \
  -o ignore/generated/decomp_build/sample_build
```

生成的工程主要包含：

- `ghidra_types.h`：Ghidra `undefined*` 等伪类型定义。
- `compat.h`：跨平台和系统接口兼容定义。
- `function_prototypes.h`：跨文件函数声明。
- `globals.h`：全局变量外部声明。
- `data_defs.c`：从二进制数据段恢复的数据定义。
- 修复后的各函数 `.c` 文件。
- `Makefile` 和 `build.ps1`。

Linux 下可直接编译：

```bash
make -C ignore/generated/decomp_build/sample_build
```

如果拥有 GNU ld map 文件，可以在生成工程时传入 `--map <文件>`，用于过滤静态链接进二进制的系统库函数。各个独立子命令如下：

```bash
python plugins/decompile_helper.py types -o ghidra_types.h
python plugins/decompile_helper.py prototypes <decomp_dir> -o function_prototypes.h
python plugins/decompile_helper.py globals <binary> <decomp_dir> -o globals.h
python plugins/decompile_helper.py extract <binary> <decomp_dir> -o data_defs.c
```

详细说明见 `plugins/decompile_helper_usage.txt`。

### 3. 自动静态修复闭环

不使用网络和 API Key 的规则模式：

```bash
python plugins/orchestrator.py \
  sample.exe \
  ignore/generated/decomp_out/sample_decomp \
  -o ignore/generated/decomp_build/sample_build \
  --proposer fallback
```

该命令会重新生成工程、应用持久化补丁、调用编译器、解析错误，并重复修复。补丁默认保存在构建目录的 `patches.json` 中。使用 `--no-prepare` 可以跳过重新生成工程，直接修复已有构建目录。

LLM 模式需要配置兼容接口：

```bash
export LLM_API_KEY="your-api-key"
export LLM_BASE_URL="https://api.deepseek.com/v1"   # 可选
export LLM_MODEL="deepseek-chat"                    # 可选

python plugins/orchestrator.py \
  sample.exe \
  ignore/generated/decomp_out/sample_decomp \
  -o ignore/generated/decomp_build/sample_build \
  --proposer llm
```

不要把 API Key 写进源码或提交到 Git；`.env` 文件已被忽略，但程序不会自动读取它，需要在启动前通过 shell 或其他方式载入环境变量。LLM 模式会将相关源码、错误信息或汇编证据发送给所配置的接口。

调度器支持 `--max-iter`（默认 10）、`--patches`（指定补丁文件）、`--rules-file`（自定义规则）、`--map` 和 `--make-cmd`。达到轮数上限、没有可用补丁或无法解析错误时会停止并返回失败。`llm.py` 的实际默认模型为 `deepseek-chat`，可通过 `LLM_MODEL` 或 `--model` 覆盖。

### 4. 专项修复工具

手动应用函数签名：

`plugins/sigs.json` 当前是针对 `apply_op` 的示例；使用前按真实函数名或地址修改，例如：

```json
[
  {"name": "apply_op", "signature": "int apply_op(int op, int a, int b)"}
]
```

```bash
python plugins/fix_signatures.py sample.exe \
  --signatures plugins/sigs.json \
  -o ignore/generated/decomp_out/sample_decomp
```

用 LLM 推断并回灌函数签名：

```bash
python plugins/fix_signatures_llm.py sample.exe \
  --prescreen \
  --build-dir ignore/generated/decomp_build/sample_build \
  -o ignore/generated/decomp_out/sample_decomp
```

用 LLM 修复函数体类型问题：

签名回灌只更新 Ghidra/反编译输出，已有构建目录不会随之更新。先重新执行上面的 `decompile_helper.py all ...` 命令，再运行：

```bash
python plugins/fix_types_llm.py \
  sample.exe \
  ignore/generated/decomp_out/sample_decomp \
  --build-dir ignore/generated/decomp_build/sample_build
```

`fix_signatures_llm.py` 支持 `--functions`、`--max-functions`、`--no-sort`；两个 LLM 专项工具都支持 `--model` 和 `--slow-model`。`--prescreen` 必须同时提供已有的 `--build-dir`。类型工具直接修改构建目录中的 `.c`，随后应先编译检查；重新生成工程可能覆盖这些修复，应事先备份或保存补丁。

补齐实际触发编译错误的未声明符号：

```bash
python plugins/fix_undeclared.py \
  sample.exe ignore/generated/decomp_build/sample_build
```

根据调用点投票修正参数数量：

```bash
python plugins/fix_argcount.py \
  ignore/generated/decomp_build/sample_build
```

`fix_undeclared.py --log <文件>` 可以使用已有编译日志；当前没有 `--map` 参数。`fix_argcount.py` 支持 `--min-votes`（默认 2），且要求相同参数数量至少占调用点的 90%；它尽量保留已有参数类型。`--dry-run` 不改源码，但仍会调用 Make 来收集错误。建议先使用相应命令的 `--help` 检查完整参数。

### 5. 图形界面

安装 PySide6 后运行：

```bash
python plugins/decompile_gui.py
```

Windows 用户也可以双击 `plugins/启动反编译器.bat`。批处理文件使用系统 `PATH` 中的 `pythonw`，因此应确保对应 Python 环境已安装 PySide6 和项目所需依赖。

GUI 支持文件树、代码预览、日志和主题设置，单个输入时可以生成工程、修复签名和运行编译修复。默认工作目录位于输入旁的 `<stem>_work/`，多个输入时为 `batch_work/`，这些目录已被 Git 忽略。界面部分打开目录操作使用 Windows API，Linux/WSL 用户建议优先使用 CLI。

## `plugins/` 文件说明

### 核心反编译和工程生成

- `decompile_binary.py`：PyGhidra 无界面批量反编译 CLI。负责输入发现、Ghidra 启动、项目创建、自动分析、函数筛选、代码导出、并行执行、状态恢复和元数据输出。
- `decompile_binary_usage.txt`：上述 CLI 的详细参数、环境配置和使用示例。
- `decompile_helper.py`：把一函数一文件的 Ghidra 伪 C 代码整理为可编译工程；生成类型、声明、全局数据和构建脚本，并执行常见语法及类型改写。
- `decompile_helper_usage.txt`：工程生成器的子命令、输出结构和编译说明。
- `decompile_gui.py`：基于 PySide6 的桌面入口。支持拖放二进制、启动反编译、生成工程、执行静态修复、浏览文件和查看日志。
- `启动反编译器.bat`：Windows GUI 启动脚本，从脚本所在目录调用 `pythonw decompile_gui.py`。

### 编译错误与函数信息修复

- `orchestrator.py`：静态修复总调度器。负责准备干净构建目录、重放补丁、运行 Make、解析 GCC 错误，并调用规则或 LLM 提议器迭代生成补丁。
- `patch.py`：持久化补丁引擎。补丁以 JSON 数组保存，支持精确 `replace` 和正则 `regex` 两种操作，可从干净基础重复应用。
- `llm.py`：补丁提议器实现。`FallbackProposer` 使用本地确定性规则；`LLMProposer` 调用 OpenAI Chat Completions 兼容接口生成补丁。
- `fix_signatures.py`：手动签名回灌工具。读取 JSON 中的函数名或地址及 C 签名，通过 Ghidra API 修改签名并可重新反编译指定函数。
- `sigs.json`：`fix_signatures.py` 的签名配置示例，格式为 `{name/address, signature}` 对象数组。
- `fix_signatures_llm.py`：LLM 函数签名修复器。导出伪代码、汇编和交叉引用作为证据，推断返回值及参数类型，回灌 Ghidra 后重新反编译；支持编译预筛和高频函数优先。
- `fix_types_llm.py`：LLM 函数体类型修复器。根据数组赋值、指针/整数混用、结构体成员等编译错误生成并应用源码补丁。
- `fix_undeclared.py`：未声明符号修复器。只处理编译日志中实际出现的 `undeclared` 名称，并结合 ELF/PE 符号信息补充函数声明或数据定义。
- `fix_argcount.py`：参数数量修复器。从 `too few/many arguments` 错误定位函数，统计调用点的实参数量并按多数结果修改声明和定义。

### 项目说明

- `work.txt`：历史工作流程、环境变量、脚本关系、推荐执行顺序和技术边界。
- `新增功能使用说明.txt`：对静态修复闭环、LLM 签名/类型修复、GUI 和测试功能的补充说明。

这些已有说明文件中的部分路径和参数沿用整理前布局；从根目录执行时应使用 `plugins/` 前缀，测试资源使用 `tests/` 前缀。参数冲突时以当前源代码和本 README 为准。

## `tests/` 内容与测试方法

- `test_core.py`：核心纯函数单元测试，覆盖文本改写、签名解析、错误解析、补丁引擎等。
- `test_golden.py`：黄金回归测试，对固定伪 C 输入执行整体修复并核对关键输出。
- `test_e2e.py`：端到端测试，以固定反编译样本生成工程，再调用 Make 验证能否成功编译。
- `test_complex.o`：端到端测试使用的 ELF 目标文件。
- `test_out_fixed/`：端到端测试使用的固定反编译 `.c` 样本。
- `error.md`：GCC 常见 C 编译错误、典型信息和原因汇总。
- `result.txt`：项目在较大二进制样本上的分阶段实验结果和技术结论。

`result.txt` 是历史记录，不代表当前环境重新运行的测试结果。固定测试样本属于版本管理内容：`.gitignore` 显式保留 `tests/test_complex.o`，也不会忽略 `tests/test_out_fixed/`。

安装 pytest 后运行：

```bash
# 全部测试
python -m pytest -q tests

# 不启动 Ghidra JVM 的核心与黄金测试
python -m pytest -q tests/test_core.py tests/test_golden.py

# 端到端工程生成与编译测试（需要 Make/GCC）
python -m pytest -q tests/test_e2e.py
```

## 推荐开发约定

- 从仓库根目录运行文档中的命令，便于路径保持一致。
- 新的项目实现、CLI 和公开使用说明放入 `plugins/`。
- 新的测试代码与可复现的小型测试样本放入 `tests/`。
- Ghidra、虚拟环境、反编译输出、构建目录、日志和私人文档放入 `ignore/`。
- 运行 `git status` 后，只提交源码、公开文档与必要测试资产；不要提交 API Key、本机路径或大体积可再生成文件。
- 修改实现后至少运行 `python -m py_compile plugins/*.py`；具备 pytest 环境时再运行相关测试。
