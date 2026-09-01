# Decompiling Binary Code with Large Language Models

用大语言模型辅助反编译二进制代码 —— 大学生创新训练项目（2026）。

Ghidra 自带的 C 反编译器能够输出伪 C 代码，但产物默认**无法直接编译**，且缺少跨文件的类型定义、函数声明与全局数据。本项目从工具链层面解决「批量反编译」与「反编译输出可编译化」两个问题，为后续基于大语言模型的反编译结果优化与语义恢复打下基础。

## 当前进度

| 模块 | 状态 | 说明 |
|---|---|---|
| 批处理插件 `plugins/decompile_binary.py` | ✅ v2.0.0 | 基于 PyGhidra headless 的批量反编译脚本 |
| 优化插件 `plugins/decompile_helper.py` | ✅ v1.0.0 | 将反编译伪代码补齐为可编译、可链接的工程 |
| 8 维测试数据集（本地） | ✅ | 覆盖控制流、数据类型、函数调用、宏/内联汇编等 |
| `control_flow` 维度反编译流水线 | ✅ | 反编译 → 补齐 → 编译链接已打通 |
| 其余 7 个维度反编译 | 🚧 进行中 | 数据已就绪，流水线陆续推进 |

> 注：测试数据集与反编译产物体积较大且含生成文件，未随仓库分发。

## 目录结构

```
.
├── plugins/                  # 两个插件源码 + 使用说明
│   ├── decompile_binary.py   # 批处理插件（PyGhidra 批量反编译）
│   ├── decompile_binary_usage.txt
│   ├── decompile_helper.py   # 优化插件（补齐为可编译工程）
│   └── decompile_helper_usage.txt
└── README.md
```

## 快速开始

### 1. 批量反编译（批处理插件）

```bash
# 需要 Ghidra 安装路径 + pyghidra
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# 反编译单个文件 / 整个目录 / 通配符
python plugins/decompile_binary.py sample.exe -o ./out
python plugins/decompile_binary.py ./input_dir -o ./out --recursive
python plugins/decompile_binary.py "*.dll" -o ./decomp --parallel 4
```

### 2. 补齐为可编译工程（优化插件）

```bash
# 一键生成完整工程（含 ghidra_types.h / function_prototypes.h /
#                     globals.h / data_defs.c / Makefile）
python plugins/decompile_helper.py all <binary> <decomp_dir> -o ./build

cd build && make
```

两个插件的详细参数与示例见各自目录下的 `*_usage.txt`。

## 环境要求

- **批处理插件**：Python 3、Ghidra（通过 `GHIDRA_INSTALL_DIR` 或 `--ghidra-dir` 指定）、`pyghidra` 包
- **优化插件**：仅需 Python 3（不依赖 Ghidra 运行环境，可在任意机器上把反编译产物补齐为可编译工程）

## 说明

- 测试数据集中的源代码为 AI 生成、经人工审核，主要用于验证反编译与优化流水线的正确性。
- 已知局限：不可恢复跳转表、复杂全局变量类型、静态链接 CRT 等情况仍需人工处理，详见 `plugins/decompile_helper_usage.txt`。
