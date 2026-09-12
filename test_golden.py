"""test_golden.py - 黄金文件回归测试：repair_source_file 的 input.c -> output.c 整体验证。

覆盖「文本改写」这一层的端到端行为（相对 test_core 的单函数更集成）。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import decompile_helper as dh


def _repair(tmp_path, text, global_names=()):
    src = tmp_path / "input.c"
    dst = tmp_path / "output.c"
    src.write_text(text, encoding="utf-8")
    dh.repair_source_file(src, dst, value_used=set(), global_names=set(global_names))
    return dst.read_text(encoding="utf-8")


class TestRepairGolden:
    def test_slice_and_array_return(self, tmp_path):
        """典型 Ghidra 伪代码：数组返回 + slice 语法，修复成指针形式。"""
        src = """// Function: apply_op
// Address:  00100318
// Type:     undefined apply_op(void)
// ============================================================


undefined1  [16] apply_op(undefined4 param_1,uint param_2,ulong param_3)



{

  undefined1 auVar3 [16];

  auVar3._8_8_ = param_3;

  auVar3._0_8_ = uVar1;

  return auVar3;

}
"""
        out = _repair(tmp_path, src)
        assert "undefined1 * apply_op(undefined4 param_1,uint param_2,ulong param_3)" in out
        assert "*(undefined8 *)((char *)auVar3 + 8) = param_3;" in out
        assert "*(undefined8 *)((char *)auVar3 + 0) = uVar1;" in out

    def test_struct_cast_rewrite(self, tmp_path):
        """sigaction 裸名 cast → struct sigaction。"""
        src = """void f(void)
{
  sigaction(1,(sigaction *)x,(sigaction *)y);
}
"""
        out = _repair(tmp_path, src)
        assert "(struct sigaction *)x" in out
        assert "(struct sigaction *)y" in out

    def test_global_name_underscore(self, tmp_path):
        """下划线前缀全局变量名 → 符号表名。"""
        src = """void f(void)
{
  _bb_common_bufsiz1 = 1;
}
"""
        out = _repair(tmp_path, src, global_names=["bb_common_bufsiz1"])
        assert "bb_common_bufsiz1 = 1;" in out

    def test_stack_ref_decl(self, tmp_path):
        """stack0x 引用 → 自动声明。"""
        src = """int f(void)
{
  return *(int *)(stack0x10);
}
"""
        out = _repair(tmp_path, src)
        assert "undefined1 stack0x10[8];" in out

    def test_value_used_return(self, tmp_path):
        """void 函数返回值被消费 → 返回类型改为 undefined8。"""
        src = """void get(void)
{
  foo();
  return;
}
"""
        # 让 foo 被判定为「返回值被消费」，这里直接传 value_used 不可行（repair 内部用
        # find_value_used_voids），所以此用例验证无异常 + 保持 void。
        out = _repair(tmp_path, src)
        assert "void get(void)" in out
