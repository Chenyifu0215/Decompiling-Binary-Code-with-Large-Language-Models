# Decompiling Binary Code with Large Language Models

用大语言模型辅助反编译二进制代码 —— 大学生创新训练项目（2026）。

Ghidra 自带的 C 反编译器能够输出伪 C 代码，但产物默认**无法直接编译**，且缺少跨文件的类型定义、函数声明与全局数据。本项目从工具链层面解决「批量反编译」与「反编译输出可编译化」两个问题，为后续基于大语言模型的反编译结果优化与语义恢复打下基础。

## 文件夹分类原则

```text
.
├── plugins/   项目实现：核心模块、CLI、GUI、配置示例和使用说明
├── tests/     项目验证：测试代码、固定样本、错误资料和实验结果
├── ignore/    本地内容：第三方工具、虚拟环境、生成物、配置和私有资料
├── README.md  项目总览与入口文档
└── .gitignore Git 忽略规则
```

- 能构成项目功能、需要协作维护的实现代码和公开说明放入 `plugins/`。
- 用于验证功能或记录实验表现的测试代码、输入样本和结果放入 `tests/`。
- 可重新安装或重新生成、与具体电脑有关、包含个人信息或不应公开的内容放入 `ignore/`。
- `ignore/` 整体不进入 Git；当前细分为 `tools/`、`envs/`、`generated/`、`local/` 和 `private/`。

## 当前进度

| 模块 | 状态 | 说明 |
|---|---|---|
| 批处理插件 `plugins/decompile_binary.py` | ✅ v2.0.0 | 基于 PyGhidra headless 的批量反编译脚本 |
| 优化插件 `plugins/decompile_helper.py` | ✅ v1.0.0 | 将反编译伪代码补齐为可编译、可链接的工程 |
| 静态修复工具链 `plugins/fix_*.py` | ✅ | 冲突/未声明/参数数/位运算/LLM 签名与类型修复 |
| 静态修复闭环 `plugins/orchestrator.py` | ✅ | 编译 — 报错 — 补丁 — 重编译迭代 |
| 8 维测试数据集（本地） | ✅ | 覆盖控制流、数据类型、函数调用、宏/内联汇编等 |
| 桌面界面 `plugins/decompile_gui.py` | ✅ | PySide6 拖拽式 GUI |

> 注：测试数据集与反编译产物体积较大且含生成文件，不随仓库分发，本地生成物统一放在 `ignore/generated/`。

## 目录结构

```text
.
├── plugins/                      # 项目实现与公开说明
│   ├── decompile_binary.py       # 批处理反编译（PyGhidra）
│   ├── decompile_binary_usage.txt
│   ├── decompile_helper.py       # 生成可编译工程
│   ├── decompile_helper_usage.txt
│   ├── decompile_gui.py          # PySide6 桌面界面
│   ├── 启动反编译器.bat           # Windows GUI 启动脚本
│   ├── orchestrator.py           # 静态修复总调度器
│   ├── patch.py                  # 补丁引擎
│   ├── llm.py                    # LLM/fallback 提议器
│   ├── fix_signatures.py         # 手工签名回灌（sigs.json 示例）
│   ├── fix_signatures_llm.py     # LLM 签名修复
│   ├── fix_types_llm.py          # LLM 函数体类型修复
│   ├── fix_undeclared.py         # 未声明/链接期未定义符号
│   ├── fix_argcount.py           # 调用点投票修参数个数
│   ├── fix_binary_ops.py         # 指针参与运算 cast
│   ├── fix_conflicts.py          # 系统头同名函数冲突
│   ├── sigs.json
│   ├── work.txt                  # 历史工作流程与技术边界
│   └── 新增功能使用说明.txt
├── tests/                        # 项目验证
│   ├── test_core.py              # 核心纯函数单元测试
│   ├── test_golden.py            # 黄金回归测试
│   ├── test_e2e.py               # 端到端生成工程 + make 编译
│   ├── test_complex.o            # 端到端固定样本（.gitignore 显式保留）
│   ├── test_out_fixed/           # 固定反编译 .c 样本
│   ├── samples/stress/           # 可复现的小型 C 压力样本
│   ├── build_corpus.py           # 从源码批量构建动态/静态 × stripped 语料
│   ├── corpus_example.json       # 本地样本构建矩阵示例
│   ├── corpus_github_example.json # GitHub 项目构建配方示例
│   ├── fetch_github_bins.py      # 抓取 GitHub Release 预编译动态+stripped 样本
│   ├── github_bins_example.json  # 抓取配方（repo/tag/asset）
│   ├── check_leak.py             # 评估公正性检查（禁止偷用 unstripped 信息）
│   └── result.txt                # 分阶段实验结果
├── ignore/                       # 本地内容，不进 Git
│   ├── tools/                    # 第三方工具（如 Ghidra）
│   ├── envs/                     # 虚拟环境
│   ├── generated/                # 反编译/构建/实验生成物
│   ├── local/                    # 本机配置与临时脚本
│   └── private/                  # 私有资料（如项目交接文档）
├── README.md
└── .gitignore
```

## 快速开始

以下命令都从仓库根目录执行（`sample.exe` 等为占位路径）：

```bash
# 1. 批量反编译
python plugins/decompile_binary.py sample.exe -o ignore/generated/decomp_out

# 2. 生成可编译工程
python plugins/decompile_helper.py all \
    sample.exe ignore/generated/decomp_out/sample_decomp \
    -o ignore/generated/decomp_build/sample_build

# 3. 编译
make -C ignore/generated/decomp_build/sample_build
```

各脚本的详细参数见 `plugins/*_usage.txt`，静态修复流程与验证回退机制见
`plugins/新增功能使用说明.txt`。

## 测试

安装 pytest 后运行：

```bash
python -m pytest -q tests
```

`test_core.py` 与 `test_golden.py` 不启动 Ghidra JVM；`test_e2e.py` 需要
Make/GCC（Windows 下通过 WSL）。

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

## 环境要求

- **批处理插件**：Python 3.12、Ghidra（`GHIDRA_INSTALL_DIR` 或 `--ghidra-dir`）、`pyghidra`
- **优化插件**：仅需 Python 3（不依赖 Ghidra 运行环境）
- **编译修复**：GCC / Make（Windows 默认经 WSL 调用）
- **LLM 修复**：`LLM_API_KEY`（可选 `LLM_BASE_URL` / `LLM_MODEL`，默认 DeepSeek）

## 说明

- 测试数据集中的源代码为 AI 生成、经人工审核，主要用于验证反编译与优化流水线的正确性。
- 已知局限：不可恢复跳转表、复杂全局变量类型、SIMD 向量 slice、静态链接 CRT 等情况仍需人工处理，详见 `plugins/decompile_helper_usage.txt` 与 `tests/result.txt`。
