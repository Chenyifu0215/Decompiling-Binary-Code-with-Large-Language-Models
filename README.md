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

> 本项目的收敛标准是“生成代码能编译并链接出 `rebuilt.exe`”：`orchestrator.py` 在某一轮 `make` 返回 0 时判定成功，命令以退出码 `0` 结束。这只是静态判据——能编译链接不等同于与原二进制运行行为一致，复杂类型、跳转表、静态链接运行库和被优化掉的语义仍可能需要人工分析与动态验证（`rebuilt.exe` 也可能启动即崩溃）。

## 文件夹分类原则

本地工作区将插件仓库、Ghidra 工具和项目资料分开放置：

```text
student_create/                  工作区容器，不是 Git 仓库
├── plugin_project/              插件 Git 仓库；在这里运行 Git 和下文命令
│   ├── .git/                    原有提交历史、分支和远程配置
│   ├── plugins/                 核心模块、CLI、GUI、配置示例和使用说明
│   ├── tests/                   测试代码、固定样本和实验资料
│   ├── ignore/                  可再生成的本地环境和运行产物（按需创建）
│   ├── README.md
│   └── .gitignore
├── ghidra_tools/                Ghidra 工具与运行依赖，位于 Git 仓库外
│   ├── ghidra_12.2_PUBLIC/
│   ├── jdk-25/                 Linux JDK 25
│   ├── python_env/             Linux Python 虚拟环境
│   ├── qt_libs/                Linux GUI 共享库
│   └── runtime/                运行时设置与缓存
└── project_docs/                申报书、报告等个人项目文档，位于 Git 仓库外
```

分类遵循以下原则：

- 能构成项目功能、需要协作维护的实现代码和公开说明放入 `plugins/`。
- 用于验证功能或记录实验表现的测试代码、输入样本和结果放入 `tests/`。
- Ghidra 本体放入仓库同级的 `../ghidra_tools/`；申报书等不可再生成的资料放入 `../project_docs/`，并另行备份。
- `ignore/` 整体不进入 Git，仅用于可再生成的环境、构建结果和日志；不要把唯一一份项目文档放在这里。
- `.agents/`、`.codex/`、`.aws/` 是工作环境挂载点，保留在外层工作区目录。
- 目录迁移保留原远程地址和分支关联。在外层目录操作时使用 `git -C plugin_project status`；也可以先 `cd plugin_project` 再运行 Git。编辑器应打开 `plugin_project/` 作为代码仓库。

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

本工作区的 Linux/WSL 环境采用如下布局：

```text
../ghidra_tools/ghidra_12.2_PUBLIC/  Ghidra，位于仓库之外
../ghidra_tools/jdk-25/             JDK 25
../ghidra_tools/python_env/         Python 3.12 虚拟环境
../ghidra_tools/qt_libs/            GUI 所需的用户级共享库
```

程序优先使用有效的 `GHIDRA_INSTALL_DIR`，否则尝试仓库同级 `ghidra_tools/current/` 和 `ghidra_tools/ghidra_*/` 中的安装目录。保留多个版本时，应显式指定使用哪个版本。Linux/WSL 下从插件仓库目录执行：

```bash
export GHIDRA_INSTALL_DIR="$(cd ../ghidra_tools/ghidra_12.2_PUBLIC && pwd)"
```

Windows PowerShell 下从插件仓库目录执行：

```powershell
$env:GHIDRA_INSTALL_DIR = (Resolve-Path ..\ghidra_tools\ghidra_12.2_PUBLIC).Path
```

[Ghidra 12.2 官方发行版](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build)要求 64 位 JDK 25；旧版所用的 Java 21 不满足该版本要求。PyGhidra 需要安装在实际运行插件的 Python 环境中。这里的 JDK、Python 环境和 Qt 共享库用于 Linux/WSL，Windows 原生运行需另行配置 Windows 依赖，不能直接复用 Linux 虚拟环境。

已配置的工作区建议通过启动脚本运行，它会设置专用 Java、Python、Ghidra 路径，并优先使用系统 GCC，避免误用 Conda 编译器：

```bash
# 从 plugin_project/ 执行；无参数时启动桌面界面（需要 WSLg 或 Linux 桌面）
./scripts/run.sh

# 命令行与测试也使用同一环境
./scripts/run.sh python plugins/decompile_binary.py --help
./scripts/run.sh python -m pytest -q -p no:cacheprovider tests
```

启动脚本仅配置当前子进程，不修改系统默认 Java 或用户 shell 配置。Ghidra 的设置和缓存分别保存在 `../ghidra_tools/runtime/config/` 和 `../ghidra_tools/runtime/cache/`。

在新环境中，创建 `../ghidra_tools/python_env/` 后，可以使用锁定的依赖清单和 Ghidra 自带的 PyGhidra wheel 恢复 Python 依赖：

```bash
uv pip install --python ../ghidra_tools/python_env/bin/python \
  --find-links ../ghidra_tools/ghidra_12.2_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist \
  -r requirements.txt
```

LLM 修复仍需自行设置 `LLM_API_KEY`（以及可选的 `LLM_BASE_URL`、`LLM_MODEL`）；这些值会由启动脚本继承，不写入仓库。未配置 API Key 时可使用 `--proposer fallback`。

本地环境的版本和验证摘要记录在 `../ghidra_tools/environment.json`。2026-11-02 的验证已通过小型 ELF 样本的反编译、工程生成、编译与运行，以及 WSLg 窗口启动；测试集为 179 通过、2 失败（数据提取中的零字节保留、固定样本的 `log_message` 参数数量），这些代码问题仍待修复。

## 快速开始

以下命令都从仓库根目录执行。`sample.exe` 和 `./binaries` 是占位路径，请换成真实输入；扩展名不决定其实际二进制格式。已配置的 Linux/WSL 工作区请将下文命令的 `python` 替换为 `./scripts/run.sh python`，以加载完整运行环境。示例把运行结果写入 `ignore/generated/`，避免误提交生成物。

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

# shell 未展开通配符时，工具也会主动展开
python plugins/decompile_binary.py "tests/*.o" -o ignore/generated/decomp_out
```

默认情况下，每个输入文件会在输出目录下形成 `<文件名>_decomp/`，其中通常按函数保存 `.c` 文件。若多个输入具有相同文件名，目录名会追加由完整输入路径生成的稳定短哈希，避免相互覆盖。重名函数会在反编译前按入口地址生成唯一名称，使定义和调用保持一致。`--meta` 和 `--list-functions` 的文件也会写入对应的每文件输出目录。详细参数见 `plugins/decompile_binary_usage.txt` 或：

```bash
python plugins/decompile_binary.py --help
```

其他常用参数：

| 参数 | 用途 |
| --- | --- |
| `--single-file -O <file.c>` | 合并输出到指定 C 文件；后续工程生成流程使用按函数拆分的输出 |
| `--resume <state.json>` | 使用状态文件续跑；只有与当前输入路径和内容哈希匹配的成功记录会被跳过，建议把状态放入 `ignore/generated/` |
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

生成的 Makefile 会记录源码对生成头文件的依赖；修改 `globals.h`、函数原型或兼容头后，普通增量 `make` 会重新编译受影响的目标文件。

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

调度器支持 `--max-iter`（默认 10）、`--patches`（指定补丁文件）、`--rules-file`（自定义规则）、`--map` 和 `--make-cmd`。它同时解析 GCC 的编译错误与 ld 的链接错误（`undefined reference to`、`multiple definition of`），所以“编译通过”实际指全部目标文件编译成功且 `rebuilt.exe` 链接成功。达到轮数上限、没有可用补丁或无法解析错误时会停止并返回失败。

退出码：`0` 表示某一轮 `make` 成功，即上述收敛标准达成；`1` 表示未收敛（达到轮数上限、提议器给不出补丁，或编译失败但解析不到错误）。该退出码只反映静态构建结果，不代表运行行为正确。

LLM 相关环境变量：`LLM_CACHE`（默认 `1`，按提示词哈希缓存响应，重跑同一错误集为 0 token）、`LLM_CACHE_DIR`（默认 `~/.cache/decompile-llm`）、`LLM_MAX_TOKENS`（可选，限制单次输出长度）、`LLM_CONCURRENCY`（默认 4，仅当单轮上下文超过 `LLM_SPLIT_CHARS` 字符时才拆成多个并发请求）。`llm.py` 的实际默认模型为 `deepseek-chat`，可通过 `LLM_MODEL` 或 `--model` 覆盖。

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

`fix_undeclared.py --log <文件>` 可以使用已有编译日志；当前没有 `--map` 参数。对于可从目标文件定位的数据符号，它会同时向 `globals.h` 写入外部声明，并在 `data_defs.c` 中恢复定义和可读取的初值。`fix_argcount.py` 支持 `--min-votes`（默认 2），且要求相同参数数量至少占调用点的 90%；调整数量时会保留已有参数的类型和名称，只为新增参数生成名称。`--dry-run` 不改源码，但仍会调用 Make 来收集错误。建议先使用相应命令的 `--help` 检查完整参数。

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

## 语料构建与评测

### 构建测试语料（方案 2：自己编译 + strip）

```bash
# 本地样本：动态/静态 × -O0/-O2 × PIE/nopie，输出到 ignore/generated/corpus/
python tests/build_corpus.py --config tests/corpus_example.json

# GitHub 项目配方示例（需要对应构建工具链，按需选择）
python tests/build_corpus.py --config tests/corpus_github_example.json --only jq
```

每个样本目录按评估用途物理分离：

```text
<job>/<config>/
├── target/sample                 # 只把这个交给反编译/修复流程（stripped）
├── ground_truth/                 # 仅用于事后评分，不进入修复流程
│   ├── sample.unstripped         # 同源同参数未 strip 孪生（.text 逐字节一致）
│   ├── symbols.json              # name/address/size，用于 FUN_xxx → 真实函数名映射
│   └── sample.map
├── build.sh                      # 可复现构建命令
└── manifest.json                 # 分类、哈希、NEEDED、函数数
```

### 抓取 GitHub 预编译样本

```bash
python tests/fetch_github_bins.py --config tests/github_bins_example.json
```

按配方下载 Release 资产（`.deb` / `.tar.gz` / `.tar.xz` / `.zip`），解包后逐个判定
ELF64 x86-64 动态可执行文件：上游已 strip 的直接进 `target/`；上游未 strip 的原始
文件存入 `ground_truth/`，再单独 strip 一份进 `target/`（`stripped_upstream=false`）。
默认严格限制 target 总大小（`max_total_mb`）与单文件大小（`max_file_mb`），并按
文件大小升序填充，输出 `manifest.json`（来源 URL、sha256、interp、链接方式等）。

注意：Rust 项目近年常发布 **static-pie** 资产（无 PT_INTERP，`file` 显示
`static-pie linked`），会被自动过滤；优先选 C/C++ 项目的 Release，或各项目
`*-unknown-linux-gnu` 的 tar 包/非 musl `.deb`。

### 评估公正性（不"对着答案抄"）

- 修复流程只允许接触 `target/sample`；`ground_truth/` 只在修复结束后用于评分、
  映射函数名或运行时对比。分解/修复工具本身不读取 `sample.unstripped` 或
  `symbols.json`，目录分离是为了防止误操作。
- 每次修复后运行泄漏检查：

  ```bash
  python tests/check_leak.py \
      --sample-dir ignore/generated/corpus/<job>/<config> \
      --dirs <反编译目录> <构建目录>
  ```

  它会校验目标确实 stripped，并在产物里搜索未 strip 孪生的真实函数名（自动
  排除 libc 动态导入与 CRT/编译器符号），命中即报错。
- 需要绝对保证时，把修复流程放进容器/VM：只挂载 `target/`，`ground_truth/`
  不进入容器。
- 以下“外部知识”不属于目标孪生信息，但会显著降低修复难度，做公平对比时应
  明确是否启用并在结果里披露：`GHIDRA_SIG_PROJECTS` 项目签名表、静态链接时
  的 `--map`（map 含真实段名）、以及 `symbols.json` 派生的任何锚点。


## 动态修复 V1（已实现）

申报书中“静态编译修复 → 运行时检测 → 反馈修复”的第二阶段现已提供可运行实现。
入口是 `plugins/dynamic_repair.py`，桌面界面新增“动态修复（配置文件）”和“打开动态报告”。
当前处理 **Linux/WSL2 x86-64 ELF、可确定输出的单进程 C 命令行程序**。
输入应为静态修复后已经能够编译的工程，参考程序必须是可执行 ELF，不能直接使用 `.o`。

流程为：冻结源文件与参考二进制 → 检查编译器和 sanitizer 环境 → 重复运行参考用例 →
普通/ASan+UBSan 双构建 → 收集错误 → 生成候选补丁 → 双构建与全部修复用例回归 →
接受严格改善的补丁 → 最后执行独立评估。原始输入工程不会被直接修改。

### 先运行离线演示

在 `plugin_project/` 中：

```bash
./scripts/run.sh python scripts/demo_dynamic.py
```

演示会创建唯一的 `ignore/dynamic-demo/<时间-随机串>/`，编译参考程序，并依次回放两个补丁：
先拒绝改变合法错误退出码的补丁，再接受修复堆数组越界的补丁，最后执行独立用例。
这是**人工注入缺陷的基础设施演示**，不能用来声称真实 Ghidra 修复率或 LLM 修复效果。
命令会打印配置文件和 HTML 报告的路径；同一个配置也可在 GUI 中选择运行。

### 配置自己的工程

配置文件中的路径均相对于该 YAML 所在目录解析。以下配置可直接按实际目录填写：

```yaml
schema_version: 1
project_id: my-program
target:
  source_dir: ./static_build
  reference_binary: ./target/original
build:
  compiler: gcc
  # sources: [main.c, data_defs.c]  # 可省略：读取 helper 的静态 SRCS 列表或发现 .c
  # force_include: []             # 可省略：自动识别 helper 的四个兼容头文件
  libraries: [m]
  timeout_seconds: 60
execution:
  timeout_seconds: 3
  instrumented_timeout_seconds: 10
  max_output_bytes: 1048576
  reference_repeats: 2
  compare_stderr: false
  environment: {LC_ALL: C, TZ: UTC}
tests:
  repair_manifest: ./cases/repair.json
repair:
  proposer: llm                  # none 只评估；replay 回放离线补丁
  max_attempts: 10
  max_no_progress: 3
  max_llm_calls: 10
  max_total_tokens: 30000
  max_completion_tokens: 2000
  max_files_per_patch: 3
  max_total_seconds: 600
artifacts:
  output_dir: ./runs             # 不得与 source_dir 相互包含
  keep_rejected_candidates: false
```

普通编译固定为 `-std=gnu11 -O1 -g`；插桩编译额外使用
`-fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fno-pie -no-pie`，
编译与链接同时插桩。使用非 PIE 插桩程序减少 ASan shadow address 冲突；普通构建遵循编译器默认 PIE 设置。
当前不执行任意自定义 Makefile，也不自动支持 C++、额外资源目录或复杂链接配方。
只复制 `.c`/`.h` 文件，拒绝源目录符号链接，源文件总量上限为 8 MiB。

用例清单为 UTF-8 JSON：

```json
{
  "schema_version": 1,
  "cases": [
    {"id": "empty", "args": [], "stdin": ""},
    {"id": "file_input", "args": ["input.txt"], "stdin": "",
     "files": {"input.txt": "1 2 3\n"}, "output_files": ["result.txt"]}
  ]
}
```

每次执行使用新的临时工作目录；支持字符串参数、UTF-8 标准输入和输入文件。
退出码、stdout 原始字节和声明的输出文件内容哈希必须与参考程序一致；stderr 比较可选。
参考程序的正常非零退出码有效。参考程序崩溃、超时、超出输出限制或重复执行结果不一致时，结果不可验证。
运行器限制墙钟时间和捕获输出量，并清理进程组；它不是安全沙箱，不支持恶意程序隔离，样本应当可信。
程序主动创建新会话、后台守护进程、网络服务或非确定性程序不在 V1 支持范围内。

```bash
# 有真实 LLM_API_KEY 时使用 llm；沿用 LLM_BASE_URL、LLM_MODEL 配置。
# 不需要 LLM 时，将配置中的 proposer 改为 none。
./scripts/run.sh python plugins/dynamic_repair.py \
  --config /path/to/config.yaml \
  --evaluation-manifest /path/to/cases/heldout.json
```

独立评估清单只在修复循环结束后加载与执行，其结果不进入下一轮补丁反馈；不得与修复清单重复输入。
输入按 `args`、`stdin`、`files` 比较；改用例 ID 或 `output_files` 不会变成新的独立输入。
不传该选项时，即使所有修复用例通过，也只报告 `REPAIR_TESTS_PASSED`。
`max_total_tokens` 使用提示 UTF-8 字节数加回复上限的保守预算预留，并记录接口实际 usage；
这不是模型专用 tokenizer 的精确计费上限。无效补丁、请求失败和缓存返回都计入尝试/请求预算。
总运行时限同时覆盖模型响应等待；Linux 后端用进程定时器中断超时，退出时清理子进程并恢复信号处理器。
因此在应用中应通过独立进程调用动态 CLI，不要直接在 Python 工作线程内运行控制器。
V1 只接受现有源文件上的唯一精确文本替换，拒绝路径越界、批量正则和测试/配置文件修改。
门禁要求失败的“用例/构建类型/问题类别”集合严格缩小，不允许引入新的失败项。
sanitizer 通常只报告遇到的第一个错误，严格门禁可能拒绝“修复一个错误但暴露另一个错误”的补丁；
因此 V1 优先保守保留行为，不能保证能连续修复所有多缺陷程序。

### 结果和运行记录

| 状态 | 含义 |
| --- | --- |
| `TEST_VALIDATED` | 修复用例和独立评估用例均通过；不等于证明程序语义等价 |
| `REPAIR_TESTS_PASSED` | 修复用例通过，未提供独立评估 |
| `PARTIAL` | 已有被接受的改善，但仍有失败或预算耗尽 |
| `NO_PROGRESS` | 没有获得可接受的改善，或仅评估发现失败 |
| `STATIC_BLOCKED` | 基线普通构建或插桩构建不能编译 |
| `UNVERIFIED` | 缺少参考/用例，或参考/独立评估无效 |
| `ENVIRONMENT_ERROR` | 工具链、配置或模型凭据等条件不满足 |
| `CANCELLED` | 任务被取消，已接受快照保留 |

每次运行单独生成：

```text
runs/<时间-随机串>/
  manifest.json          # 配置、环境、工具/输入哈希与模型名
  inputs/                # 冻结的参考二进制、修复清单和回放补丁
  probe/                 # sanitizer 可用性预检
  baseline/              # 原始源快照、双构建日志及用例结果
  attempts/0001/         # 每轮证据、补丁、diff、构建结果和接受/拒绝原因
  best/                  # 最佳源代码与两个可执行版本
  accepted_patches.jsonl # 按顺序记录接受的补丁；有接受时才产生
  results.json           # 最终状态、预算与逐用例结果；原始输出以 base64 保存
  report.html            # 可直接打开的结果表格与补丁决策
```

默认移除被拒绝候选的源码副本和可执行文件，保留日志、diff 和决策证据。
采纳新版本时使用目录重命名切换最佳快照；原始工程和基线快照保留。
若运行环境限制 ptrace，LeakSanitizer 可能无法工作，预检会报告环境错误；不会通过关闭检查伪造通过。

### Linux、Windows 与 GUI

- Linux/WSL：直接运行同一套 Python 后端，依赖 GCC、ASan/UBSan runtime 和 PyYAML。
- Windows：`python plugins/dynamic_repair.py --config config.yaml` 自动通过 `wsl.exe` 调用同一入口。
  配置内使用相对路径；可指定 `--wsl-distribution Ubuntu --wsl-python /path/to/venv/bin/python`。
  `--wsl-python` 默认是 WSL 的 `python3`，它必须已装 PyYAML。
- Windows GUI 使用环境变量 `DYNAMIC_WSL_PYTHON`、`DYNAMIC_WSL_DISTRIBUTION` 选择同一环境。
  先选择 YAML，再选择可选的独立评估 JSON；取消第二个选择框表示只执行修复测试。
- Linux/WSL 后端与 Qt 界面动作已在当前 WSL 环境验证；Windows 路径转换/委托有自动化测试，原生 Windows GUI、
  真实 WSL 发行版选择及 Windows 强制取消仍需在 Windows 交互会话联调，不能据此声称已全面适配。

### 新增模块职责

| 文件 | 职责 |
| --- | --- |
| `plugins/dynamic_repair.py` | CLI、Windows→WSL 委托、取消信号与退出状态 |
| `plugins/dynamic/config.py` | YAML/用例 schema 校验、相对路径和预算配置 |
| `plugins/dynamic/builder.py` | 识别 helper 编译单元、双构建和编译日志 |
| `plugins/dynamic/runner.py` | 隔离工作目录、输入输出、超时/输出上限、进程组清理 |
| `plugins/dynamic/diagnostics.py` | 识别 ASan/UBSan、信号和执行失败；定义行为比较字段 |
| `plugins/dynamic/oracle.py` | 稳定性检查、参考行为采集和逐用例评估 |
| `plugins/dynamic/evidence.py` | 构造有上限的源码与运行证据，不加入独立评估反馈 |
| `plugins/dynamic/workspace.py` | 源快照、哈希、事务式补丁校验与差异记录 |
| `plugins/dynamic/validator.py` | 严格改善与无回归的接受门禁 |
| `plugins/dynamic/controller.py` | 状态机、预算、最佳版本切换与最终评估 |
| `plugins/dynamic/report.py` | JSON 结果和可独立打开的 HTML 报告 |
| `plugins/llm.py` | 复用模型连接，新增 `propose_runtime_fix` 接口 |
| `scripts/demo_dynamic.py` | 构建离线合成样本并运行完整演示 |
| `tests/dynamic_cases/` | 参考源、人工缺陷源、修复/独立清单和回放配置 |
| `tests/test_dynamic.py` | 真实编译、回归/预算/路径/超时/模型接口等验证 |
| `tests/test_dynamic_audit.py` | 独立用例去重、版本切换故障、模型异常、文件保护及取消/时限边界回归 |
| `tests/test_dynamic_gui.py` | Qt 按钮到后端的集成、关闭等待、结果加载与提前取消 |

申报书后续的 Referee/Advisor/Operator 多角色可读性重构、MSSC 评估及大型真实样本修复率实验，
仍属于下一阶段；本轮交付不把这些尚未实现的部分算入完成进度。

2026-11-02 验证记录：全量测试 `210 passed`（Qt 旧字体 API 有 6 条弃用提示）；
离线演示验证了拒绝回归、接受修复与独立测试；一个真实 Ghidra 12.2 生成的小型 C 工程也完成双构建和独立行为对照。
Qt 验证通过 offscreen 平台实际触发按钮和后台 CLI。未配置在线模型密钥，因此不声称已验证真实 LLM 的修复效果。

同日审核追加：全量回归为 **233 passed，无警告**。新增 23 项回归测试，修正了以下问题：

- 独立评估改变输出检查项时，重复输入可能被错误计入独立验证。
- 快照复制/重命名失败、取消与提交同时发生时，最佳版本和“已接受”记录可能不一致。
- 模型接口异常 JSON 结构导致未捕获异常；缓存未区分服务端点与回复预算；网络等待缺少总时限中断。
- `--result-file` 可能覆盖输入源文件；配置空路径、布尔版本号和非法文件名校验不足。
- 普通程序错误文本可能被误当成 sanitizer 报告；已知大小的数据对象可能丢失零填充或被添加额外终止字节。
- GUI 提前取消可能漏掉尚未启动的任务，关闭时可能销毁仍运行的线程，损坏的结果文件可能使槽函数异常退出。

JSON 结果现使用临时文件加原子替换写入；原始源码和接受前基线仍保留。
离线演示及现有真实 Ghidra 小样本动态验证均再次通过，Git 完整性检查未发现损坏（历史悬空对象保留）。
本次审核没有推进多角色优化等后续功能；在线 LLM 效果和真实 Windows 交互会话仍不在已验证范围内。

## 推荐开发约定

- 从仓库根目录运行文档中的命令，便于路径保持一致。
- 新的项目实现、CLI 和公开使用说明放入 `plugins/`。
- 新的测试代码与可复现的小型测试样本放入 `tests/`。
- Ghidra 放入 `../ghidra_tools/`，申报书等项目资料放入 `../project_docs/`；虚拟环境、反编译输出、构建目录和日志可放入 `ignore/`。
- 运行 `git status` 后，只提交源码、公开文档与必要测试资产；不要提交 API Key、本机路径或大体积可再生成文件。
- 修改实现后至少运行 `python -m py_compile plugins/*.py`；具备 pytest 环境时再运行相关测试。
