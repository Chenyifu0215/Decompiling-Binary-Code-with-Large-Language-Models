"""test_core.py - 核心脚本纯函数的单元测试（参考 retdec 的 gtest 模式）。

覆盖不依赖 Ghidra JVM 的纯函数：文本改写、签名解析、错误解析、补丁引擎等。
"""

import os
from pathlib import Path
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(os.path.dirname(HERE), "plugins")
sys.path.insert(0, PLUGIN_DIR)

import pytest

import decompile_helper as dh
import orchestrator as orch
import patch as patch_mod
import llm as llm_mod
import fix_argcount as fa
import fix_signatures_llm as fsllm
import fix_undeclared as fu
import decompile_binary as db


# --------------------------------------------------------------------------- #
# decompile_helper: 文本改写
# --------------------------------------------------------------------------- #

class TestSliceSyntax:
    def test_slice_8(self):
        assert dh._repair_slice_syntax("auVar3._8_8_ = x;") == \
            "*(undefined8 *)((char *)&auVar3 + 8) = x;"

    def test_slice_0_4(self):
        assert dh._repair_slice_syntax("buf._0_4_ = y;") == \
            "*(undefined4 *)((char *)&buf + 0) = y;"

    def test_unknown_size_untouched(self):
        assert dh._repair_slice_syntax("a._16_16_ = z;") == "a._16_16_ = z;"

    def test_scalar_base_uses_address(self):
        out = dh._repair_slice_syntax("undefined8 local_198;\nreturn local_198._1_7_;")
        assert "(char *)&local_198 + 1" in out

    def test_non_power_of_two_assign_is_rmw(self):
        out = dh._repair_slice_syntax(
            "undefined8 local_198;\nlocal_198._1_7_ = (undefined7)(x >> 8);")
        assert ("*(unsigned long long *)((char *)&local_198 + 1) = "
                "(*(unsigned long long *)((char *)&local_198 + 1) & "
                "~0xffffffffffffffULL) | "
                "((unsigned long long)((undefined7)(x >> 8)) & "
                "0xffffffffffffffULL);") in out

    def test_member_chain_base(self):
        out = dh._repair_slice_syntax("x = pStack_360.__sd.__val[0]._4_4_;")
        assert ("*(undefined4 *)((char *)&(pStack_360.__sd.__val[0]) + 4)"
                in out)

    def test_non_power_of_two_read_is_masked(self):
        out = dh._repair_slice_syntax("undefined8 local_198;\nreturn local_198._2_6_;")
        assert ("(*(unsigned long long *)((char *)&local_198 + 2) & "
                "0xffffffffffffULL)") in out

    def test_wide_slice_copy_memcpy(self):
        out = dh._repair_slice_syntax(
            "void f(void) {\n  undefined1 auVar1 [16];\n  undefined1 auVar2 [16];\n"
            "  auVar1._0_12_ = auVar2._0_12_;\n}")
        assert "memcpy((char *)&auVar1 + 0, (char *)&auVar2 + 0, 12);" in out

    def test_wide_slice_from_array_memcpy(self):
        out = dh._repair_slice_syntax(
            "void f(void) {\n  undefined1 auVar1 [16];\n  undefined1 auVar2 [16];\n"
            "  auVar1._0_12_ = auVar2;\n}")
        assert "memcpy((char *)&auVar1 + 0, auVar2, 12);" in out


class TestQualifiedNames:
    def test_sanitize_function(self):
        assert dh.sanitize_qualified_names(
            "int switchD_0010164e::caseD_0(int param_1)") == \
            "int switchD_0010164e_caseD_0(int param_1)"

    def test_sanitize_switchdata_ref(self):
        assert dh.sanitize_qualified_names(
            "p = &switchD_0010164e::switchdataD_00104020;") == \
            "p = &switchD_0010164e_switchdataD_00104020;"


class TestCodeCasts:
    def test_naked_code_cast(self):
        assert dh._repair_code_casts("x = (code)0x0;") == "x = (code *)0x0;"

    def test_pointer_cast_untouched(self):
        assert dh._repair_code_casts("x = (code *)0x0;") == "x = (code *)0x0;"

    def test_case_pointer_to_integer(self):
        assert dh._repair_code_casts("case (code *)0x0:") == \
            "case (unsigned long)0x0:"

    def test_case_multi_pointer_to_integer(self):
        assert dh._repair_code_casts("case (ulonglong ******)0x0:") == \
            "case (unsigned long)0x0:"


class TestAnonFuncTypes:
    def test_maps_to_code(self):
        assert dh._repair_anon_func_types(
            "extern int atexit(_func_5014 *param_1);") == \
            "extern int atexit(code *param_1);"

    def test_named_identifier_untouched(self):
        text = "int my_func_12(void);"
        assert dh._repair_anon_func_types(text) == text


class TestFuncPtrArrays:
    def test_indexed_funcptr_decl_becomes_array(self):
        text = "code *local_60;\nlocal_60[3] = x;"
        assert "code *local_60[1];" in dh._repair_funcptr_arrays(text)

    def test_unindexed_untouched(self):
        text = "code *fn;\n(*fn)(1);"
        assert dh._repair_funcptr_arrays(text) == text


class TestArgcountRewrite:
    def test_array_param_preserved(self):
        text = ("void FUN(undefined1 param_1 [16],size_t param_2,"
                "undefined8 *param_3);")
        out = fa.rewrite_params(text, "FUN", 2)
        assert "undefined1 param_1[16], size_t param_2" in out

    def test_function_pointer_param_not_split(self):
        text = "void g(void (*cb)(int,int),int x);"
        out = fa.rewrite_params(text, "g", 2)
        assert "void (*cb)(int,int)" in out


class TestDataPtrParams:
    def test_code_ptr_used_as_data(self):
        params = "ulong param_1,code *param_2,code *param_3"
        body = "x = (uint)param_3; y = param_2[4];"
        out = dh._fix_data_ptr_params(params, body)
        assert "undefined1 *param_3" in out
        assert "undefined1 *param_2" in out

    def test_function_pointer_untouched(self):
        params = "code *param_1"
        assert dh._fix_data_ptr_params(params, "(*param_1)();") == params


class TestTypeAliases:
    def test_sigaltstack_cast(self):
        assert dh._repair_type_aliases("x = (sigaltstack *)0x0;") == \
            "x = (stack_t *)0x0;"

    def test_sigaltstack_decl(self):
        assert dh._repair_type_aliases("sigaltstack local_88;") == \
            "stack_t local_88;"


class TestWidenPointerLocals:
    def test_indexed_scalar_becomes_pointer(self):
        text = "undefined4 local_1c;\nlocal_1c[1] = 0;"
        assert "undefined4 *local_1c;" in dh._widen_pointer_locals(text)

    def test_cast_assigned_scalar_becomes_pointer(self):
        text = "undefined4 local_1c;\nlocal_1c = (undefined4 *)p;"
        assert "undefined4 *local_1c;" in dh._widen_pointer_locals(text)

    def test_plain_scalar_untouched(self):
        text = "undefined4 local_1c;\nlocal_1c = 1;"
        assert dh._widen_pointer_locals(text) == text


class TestArrayCasts:
    def test_rhs_array_cast_to_integer(self):
        assert dh._repair_array_casts("x = (char [8])0x1234;") == \
            "x = (unsigned long long)0x1234;"

    def test_array_lvalue_cast(self):
        out = dh._repair_array_casts("*(char (*) [8])(p + 6) = v;")
        assert out == "*(unsigned long long *)(p + 6) = v;"


class TestAggregateCasts:
    def test_union_local_gets_address(self):
        text = ("void f(void) {\n  _union_1457 local_b00;\n"
                "  *(undefined4 *)((char *)local_b00 + 0) = 0;\n}")
        out = dh._repair_aggregate_casts(text)
        assert "(char *)&local_b00 + 0" in out

    def test_existing_address_untouched(self):
        text = ("void f(void) {\n  _union_1457 local_b00;\n"
                "  x = (char *)&local_b00;\n}")
        assert dh._repair_aggregate_casts(text) == text

    def test_array_untouched(self):
        text = "void f(void) {\n  int arr[4];\n  x = (char *)arr;\n}"
        assert dh._repair_aggregate_casts(text) == text


class TestTypesTemplate:
    def test_includes_elf_h(self):
        assert "#include <elf.h>" in dh.GHIDRA_TYPES_TEMPLATE

    def test_defines_destr_function(self):
        assert "__destr_function" in dh.GHIDRA_TYPES_TEMPLATE


class TestUndefinedRefs:
    def test_collect_link_errors(self):
        log = (
            "collect2: error: ld returned 1 exit status\n"
            "(.text+0x1b): undefined reference to `pcRam0000000000105048'\n"
            "FUN_x.c:(.text+0x45): undefined reference to "
            "`pcRam0000000000105048'\n"
            "/usr/bin/ld: x.c:(.text): undefined reference to `CONCAT71'\n"
        )
        assert fu.collect_undefined_refs(log) == [
            "pcRam0000000000105048", "CONCAT71"]

    def test_collect_excludes_known(self):
        log = "undefined reference to `foo'\nundefined reference to `bar'\n"
        assert fu.collect_undefined_refs(log, exclude={"foo"}) == ["bar"]


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

    def test_delimiters_in_literals_are_preserved(self):
        text = 'puts("stat /* literal */"); /* comment */ char c = \'/\';'
        assert dh._strip_block_comments(text) == \
            'puts("stat /* literal */");  char c = \'/\';'

    def test_delimiters_in_line_comments_are_preserved(self):
        text = "a; // /* not a block comment */\nb; /* comment */ c;"
        assert dh._strip_block_comments(text) == \
            "a; // /* not a block comment */\nb;  c;"


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

    def test_multiline_parameters(self):
        text = "int callee(int a,\n           int b)\n{\n  return a + b;\n}"
        assert dh.parse_signature(text) == ("int", "callee", "int a, int b")

    def test_name_and_parameters_on_separate_lines(self):
        text = "undefined1 [16] build\n\n  (int a,\n   int b)\n{\n}"
        assert dh.parse_signature(text) == \
            ("undefined1 *", "build", "int a, int b")


class TestStructRewrites:
    def test_rewrite_struct_types(self):
        assert dh._rewrite_struct_types("stat *p") == "struct stat *p"

    def test_no_double_struct(self):
        assert dh._rewrite_struct_types("struct stat *p") == "struct stat *p"

    def test_struct_casts(self):
        assert dh._repair_struct_casts("(sigaction *)x") == "(struct sigaction *)x"

    def test_struct_decls(self):
        assert dh._repair_struct_decls("dirent64 *p;") == "struct dirent64 *p;"

    def test_passwd_declaration_rewritten(self):
        assert dh._repair_struct_decls("passwd pw;") == "struct passwd pw;"

    def test_passwd_pointer_declaration(self):
        assert dh._repair_struct_decls("passwd *pw;") == "struct passwd *pw;"

    def test_passwd_identifier_untouched(self):
        text = "x = passwd + 1;"
        assert dh._repair_struct_decls(text) == text
    @pytest.mark.parametrize("name", ["stat64", "statfs64", "statvfs64"])
    def test_64_bit_struct_calls_are_untouched(self, name):
        text = "return %s(path, &buf);" % name
        assert dh._repair_conflicting_struct_decls(text) == text

    @pytest.mark.parametrize("name", ["stat64", "statfs64", "statvfs64"])
    def test_64_bit_struct_declarations_are_rewritten(self, name):
        text = "%s local;" % name
        assert dh._repair_conflicting_struct_decls(text) == \
            "struct %s local;" % name


class TestReturnLastCall:
    def test_wraps_return(self):
        text = "foo(a, b);\n  return;"
        assert dh._return_last_call(text) == "return foo(a, b);"

    def test_wraps_function_pointer_return_without_touching_signature(self):
        text = "void f(code *fn)\n{\n  (*fn)(1, 2);\n  return;\n}"
        assert dh._return_last_call(text) == \
            "void f(code *fn)\n{\n  return (*fn)(1, 2);\n}"

    def test_if_block_not_mangled(self):
        text = ("void f(int x)\n{\n  if (x) {\n    g(x);\n  }\n"
                "  h();\n  return;\n}")
        out = dh._return_last_call(text)
        assert "return if" not in out
        assert "return h();" in out


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
        out = dh._repair_array_assignments(text)
        assert "ghidra_copy_scalar(auVar8, foo(x)," in out
        assert "sizeof(auVar8[0]) * (16)" in out

    def test_unknown_parameter_capacity_untouched(self):
        text = "void f(undefined1 buf[])\n{\n  buf = 1;\n}\n"
        assert dh._repair_array_assignments(text) == text

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

    def test_intlit_and_ptr_assign(self):
        u = dh.collect_global_usage("DAT_10 = 1;\nDAT_20 = &DAT_30;")
        assert u["DAT_10"]["intlit"] == 1
        assert u["DAT_20"]["ptrassign"] == 1

    def test_dat_ctype_rules(self):
        usage = dh.collect_global_usage(
            "DAT_10 = 1;\nDAT_10 = 2;\n*DAT_20 = 1;\n"
            "x = DAT_30 & 3;\nDAT_40 = &DAT_50;")
        assert dh._dat_ctype("DAT_10", usage) == "unsigned long"
        assert dh._dat_ctype("DAT_20", usage) == "undefined8 *"
        assert dh._dat_ctype("DAT_30", usage) == "unsigned long"
        assert dh._dat_ctype("DAT_40", usage) == "undefined8 *"
        assert dh._dat_ctype("DAT_99", usage) is None
    def test_bitop_preserves_global_width_and_value(self):
        binary = {
            "data": b"\x78\x56\x34\x12",
            "pointer_size": 8,
            "byteorder": "little",
        }
        usage = dh.collect_global_usage("return g_seed >> 16;")
        assert dh.global_info(binary, "g_seed", 0, 4, "", usage) == \
            ("undefined4 g_seed", "0x12345678")


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

    def test_fatal_error_without_column(self):
        errs = orch.parse_errors("main.c:3: fatal error: missing.h: No such file\n")
        assert errs == [{
            "file": "main.c", "line": 3, "col": 0, "kind": "error",
            "message": "missing.h: No such file",
        }]

    def test_linker_multiple_definition(self):
        output = "/usr/bin/ld: b.o: in function `f':\nb.c:(.text+0x0): multiple definition of `f'; a.o:first defined here\n"
        errs = orch.parse_errors(output)
        assert errs[0]["kind"] == "error"
        assert errs[0]["file"] == "b.c"
        assert errs[0]["message"] == "multiple definition of 'f'"


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


class TestApplyConfig:
    def test_path_and_numeric_fields_are_converted(self, tmp_path):
        from argparse import Namespace

        args = Namespace(output_dir=None, output_file=None, project_dir=None,
                         ghidra_dir=None, resume=None, log_file=None,
                         parallel=0, timeout=0, max_memory=None)
        configured = db.apply_config(args, {
            "output_dir": str(tmp_path / "out"),
            "output_file": str(tmp_path / "all.c"),
            "project_dir": str(tmp_path / "projects"),
            "ghidra_dir": str(tmp_path / "ghidra"),
            "resume": str(tmp_path / "state.json"),
            "log_file": str(tmp_path / "logs" / "run.log"),
            "parallel": "3",
            "timeout": "60",
            "max_memory": 4096,
        })
        for field in ["output_dir", "output_file", "project_dir", "ghidra_dir",
                      "resume", "log_file"]:
            assert isinstance(getattr(configured, field), Path)
        assert configured.parallel == 3
        assert configured.timeout == 60
        assert configured.max_memory == "4096"


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


class TestInferSignature:
    def test_zero_parameter_signature_is_valid(self):
        proposer = llm_mod.LLMProposer(api_key="test")
        proposer._chat_json = lambda *args: {"return_type": "int", "params": []}
        assert proposer.infer_signature("f", "int f(int x)", "", "", "") == \
            ("int", [])


# --------------------------------------------------------------------------- #
# fix_argcount: 参数声明改写
# --------------------------------------------------------------------------- #

class TestRewriteParams:
    def test_existing_names_are_preserved_when_adding(self):
        text = "int add(int a,int b)\n{ return a+b; }\n"
        assert fa.rewrite_params(text, "add", 3) == \
            "int add(int a, int b, undefined8 param_3)\n{ return a+b; }\n"

    def test_pointer_declaration_is_preserved(self):
        text = "int f(char *name, unsigned long count);"
        assert fa.rewrite_params(text, "f", 3) == \
            "int f(char *name, unsigned long count, undefined8 param_3);"

    def test_added_name_does_not_collide(self):
        text = "int f(int param_2);"
        assert fa.rewrite_params(text, "f", 2) == \
            "int f(int param_2, undefined8 param_2_2);"


class TestCollectArgVotes:
    def test_definition_and_non_code_are_not_calls(self, tmp_path):
        (tmp_path / "calls.c").write_text(
            "int f(int a, int b)\n"
            "{ return a + b; }\n"
            "int g(void)\n"
            "{\n"
            "  // f(1, 2, 3)\n"
            "  puts(\"f(1, 2, 3, 4)\");\n"
            "  return f(1) + f(2);\n"
            "}\n",
            encoding="utf-8",
        )
        assert fa.collect_arg_votes(tmp_path, ["f"])["f"] == {1: 2}


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
