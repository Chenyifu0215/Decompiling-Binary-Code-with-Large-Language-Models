"""test_core.py - 核心脚本纯函数的单元测试（参考 retdec 的 gtest 模式）。

覆盖不依赖 Ghidra JVM 的纯函数：文本改写、签名解析、错误解析、补丁引擎等。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

import decompile_helper as dh
import orchestrator as orch
import patch as patch_mod
import llm as llm_mod
import fix_signatures_llm as fsllm
import decompile_binary as db


# --------------------------------------------------------------------------- #
# decompile_helper: 文本改写
# --------------------------------------------------------------------------- #

class TestSliceSyntax:
    def test_slice_8(self):
        assert dh._repair_slice_syntax("auVar3._8_8_ = x;") == \
            "*(undefined8 *)((char *)auVar3 + 8) = x;"

    def test_slice_0_4(self):
        assert dh._repair_slice_syntax("buf._0_4_ = y;") == \
            "*(undefined4 *)((char *)buf + 0) = y;"

    def test_unknown_size_untouched(self):
        assert dh._repair_slice_syntax("a._16_16_ = z;") == "a._16_16_ = z;"


class TestStackRefs:
    def test_declares_stack(self):
        out = dh._repair_stack_refs("int f() {\n  return stack0x10;\n}")
        assert "undefined1 stack0x10[8];" in out

    def test_no_stack_untouched(self):
        assert dh._repair_stack_refs("int f() {\n  return 1;\n}") == \
            "int f() {\n  return 1;\n}"


class TestStripBlockComments:
    def test_strips(self):
        assert dh._strip_block_comments("a /* c */ b") == "a  b"

    def test_multiline(self):
        assert dh._strip_block_comments("a /* c1\nc2 */ b") == "a  b"


class TestParseSignature:
    def test_returns_tuple(self):
        assert dh.parse_signature("int apply_op(int op, int a, int b)") == \
            ("int", "apply_op", "int op, int a, int b")

    def test_array_return_normalized(self):
        ret, name, params = dh.parse_signature("undefined1  [16] f(uint x)")
        assert ret == "undefined1 *"
        assert name == "f"

    def test_skips_comments(self):
        text = "// Function: f\n// Type: x\n\nint f(int a)"
        assert dh.parse_signature(text) == ("int", "f", "int a")


class TestStructRewrites:
    def test_rewrite_struct_types(self):
        assert dh._rewrite_struct_types("stat *p") == "struct stat *p"

    def test_no_double_struct(self):
        assert dh._rewrite_struct_types("struct stat *p") == "struct stat *p"

    def test_struct_casts(self):
        assert dh._repair_struct_casts("(sigaction *)x") == "(struct sigaction *)x"

    def test_struct_decls(self):
        assert dh._repair_struct_decls("dirent64 *p;") == "struct dirent64 *p;"


class TestReturnLastCall:
    def test_wraps_return(self):
        text = "foo(a, b);\n  return;"
        assert dh._return_last_call(text) == "return foo(a, b);"


class TestMergeSplitArrayReturn:
    def test_merges(self):
        text = "undefined1  [16]\n\nbb_simplify_path(char *p)\n{"
        out = dh._merge_split_array_return(text)
        assert "undefined1  [16] bb_simplify_path(char *p)" in out

    def test_plain_untouched(self):
        text = "int f(int a)\n{\n  return a;\n}"
        assert dh._merge_split_array_return(text) == text


class TestConflictingStructDecls:
    def test_local_decl(self):
        assert dh._repair_conflicting_struct_decls("stat local_d0;") == \
            "struct stat local_d0;"

    def test_call_untouched(self):
        assert dh._repair_conflicting_struct_decls("stat(path, &buf);") == \
            "stat(path, &buf);"

    def test_pointer_decl(self):
        assert dh._repair_conflicting_struct_decls("sigaction *p;") == \
            "struct sigaction *p;"

    def test_no_double_struct(self):
        assert dh._repair_conflicting_struct_decls("struct stat x;") == \
            "struct stat x;"


class TestArrayAssignments:
    def test_rewrites_array_assign(self):
        text = "undefined1 auVar8 [16];\n  auVar8 = foo(x);\n"
        assert "*(undefined8 *)auVar8 = foo(x);" in \
            dh._repair_array_assignments(text)

    def test_index_assign_untouched(self):
        text = "undefined1 auVar8 [16];\n  auVar8[0] = 1;\n"
        assert "auVar8[0] = 1;" in dh._repair_array_assignments(text)

    def test_non_array_untouched(self):
        text = "int y = 1;\n  y = z;\n"
        assert dh._repair_array_assignments(text) == text


class TestGlobalUsage:
    def test_deref(self):
        assert dh.collect_global_usage("*bb_errno = 1;")["bb_errno"]["deref"] == 1

    def test_bitop(self):
        u = dh.collect_global_usage("x = option_mask32 & 1;")
        assert u["option_mask32"]["bitop"] >= 1


# --------------------------------------------------------------------------- #
# orchestrator: 错误解析 / 路径
# --------------------------------------------------------------------------- #

class TestParseErrors:
    def test_compile_error(self):
        errs = orch.parse_errors("foo.c:12:5: error: too many arguments\n")
        assert errs[0]["file"] == "foo.c"
        assert errs[0]["line"] == 12
        assert errs[0]["kind"] == "error"

    def test_undefined_reference(self):
        out = "/usr/bin/ld: bar.c:(.text+0xd): undefined reference to `x'\n"
        errs = orch.parse_errors(out)
        assert errs[0]["message"] == "undefined reference to 'x'"
        assert errs[0]["file"] == "bar.c"

    def test_warning_not_error(self):
        errs = orch.parse_errors("f.c:1:1: warning: unused\n")
        assert errs[0]["kind"] == "warning"


# --------------------------------------------------------------------------- #
# fix_signatures_llm: 类型名映射 / 名称过滤
# --------------------------------------------------------------------------- #

class TestNormalizeType:
    def test_longlong(self):
        assert fsllm._normalize_type("longlong x") == "long long x"

    def test_uchar(self):
        assert fsllm._normalize_type("int f(uchar c)") == "int f(unsigned char c)"

    def test_no_double_map(self):
        assert fsllm._normalize_type("long long x") == "long long x"


class TestSkipName:
    def test_underscore(self):
        assert fsllm._skip_name("_init") is True

    def test_cold(self):
        assert fsllm._skip_name("foo.cold") is True

    def test_normal(self):
        assert fsllm._skip_name("bb_strtou") is False


# --------------------------------------------------------------------------- #
# decompile_binary: 签名注入纯函数（libc 内联别名规范化 + 名字语义签名表）
# --------------------------------------------------------------------------- #

class TestNormalizeLibcName:
    def test_isoc_prefix(self):
        assert db._normalize_libc_name("__isoc99_sscanf") == "sscanf"

    def test_isoc_digit(self):
        assert db._normalize_libc_name("__isoc23_strtoumax") == "strtoumax"

    def test_gi_prefix(self):
        assert db._normalize_libc_name("__GI_strlen") == "strlen"

    def test_version_suffix(self):
        assert db._normalize_libc_name("__ieee754_sqrt@GLIBC_2.2.5") == "sqrt"

    def test_plain_untouched(self):
        assert db._normalize_libc_name("memcpy") == "memcpy"


class TestMatchNameSignature:
    def test_xmalloc(self):
        assert db.match_name_signature("xmalloc") == \
            ("void *", ["unsigned long size"])

    def test_no_match(self):
        assert db.match_name_signature("random_func_name") is None

    def test_fullmatch_not_partial(self):
        assert db.match_name_signature("xmalloc_extra") is None

    def test_project_table_loaded_on_demand(self):
        assert db.match_name_signature("bb_strtou") is None
        ret, params = db.match_name_signature("bb_strtou", projects=["busybox"])
        assert ret == "unsigned long"
        assert len(params) == 3


class TestParamTypeNames:
    def test_strips_arg_names(self):
        assert fsllm.param_type_names(["char *arg", "int base"]) == \
            ["char *", "int"]

    def test_pointer_to_pointer(self):
        assert fsllm.param_type_names(["char **endp"]) == ["char **"]

    def test_bare_type_untouched(self):
        assert fsllm.param_type_names(["char *"]) == ["char *"]


# --------------------------------------------------------------------------- #
# llm: 代码围栏剥离
# --------------------------------------------------------------------------- #

class TestStripCodeFence:
    def test_strips_fence(self):
        assert llm_mod._strip_code_fence("```json\n{\"a\":1}\n```") == '{"a":1}'

    def test_no_fence(self):
        assert llm_mod._strip_code_fence('{"a":1}') == '{"a":1}'


# --------------------------------------------------------------------------- #
# patch: 补丁引擎
# --------------------------------------------------------------------------- #

class TestApplyPatchList:
    def setup_method(self):
        self.d = str(os.path.join(os.path.dirname(__file__), "_patch_test_tmp"))
        os.makedirs(self.d, exist_ok=True)
        with open(os.path.join(self.d, "t.c"), "w") as f:
            f.write("int x = 1;\nint y = 1;\n")

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_replace(self):
        applied, errs = patch_mod.apply_patch_list(
            self.d, [{"op": "replace", "file": "t.c", "old": "int x = 1;", "new": "int x = 2;"}])
        assert applied == 1 and not errs

    def test_replace_not_found(self):
        _, errs = patch_mod.apply_patch_list(
            self.d, [{"op": "replace", "file": "t.c", "old": "nope", "new": "x"}])
        assert any("not found" in e for e in errs)

    def test_empty_old_rejected(self):
        _, errs = patch_mod.apply_patch_list(
            self.d, [{"op": "replace", "file": "t.c", "old": "", "new": "x"}])
        assert any("non-empty" in e for e in errs)

    def test_regex(self):
        applied, _ = patch_mod.apply_patch_list(
            self.d, [{"op": "regex", "file": "t.c",
                      "pattern": r"int y = 1;", "repl": "int y = 2;"}])
        assert applied == 1

    def test_count_single(self):
        applied, _ = patch_mod.apply_patch_list(
            self.d, [{"op": "replace", "file": "t.c", "old": "1", "new": "2", "count": 1}])
        assert applied == 1
        text = open(os.path.join(self.d, "t.c")).read()
        assert text.count("2") == 1  # 只替换一处


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
