#!/usr/bin/env python3
"""decompile_helper.py - Make decompile_binary.py output compilable.

Pairs with the per-function C files produced by decompile_binary.py without
modifying them. Ghidra's decompiler emits pseudo-C (undefined* types, raw
address data references, no prototypes), which does not compile as-is. This
script generates the missing pieces:

  types        write ghidra_types.h (typedefs for Ghidra pseudo types)
  prototypes   write function_prototypes.h (cross-file declarations)
  extract      write data_defs.c (DAT_* data + named globals from the binary)
  all          run everything into a build/ dir + Makefile + build.ps1

Examples:
  python decompile_helper.py types -o ghidra_types.h
  python decompile_helper.py prototypes decomp_output/bomb_linux_decomp
  python decompile_helper.py extract bomb_linux decomp_output/bomb_linux_decomp
  python decompile_helper.py all bomb_linux decomp_output/bomb_linux_decomp
"""

import argparse
import re
import struct
import sys
from pathlib import Path


def _write_text_if_changed(path, text):
    """Write only when content differs, preserving mtimes for incremental builds."""
    path = Path(path)
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except OSError:
        pass
    path.write_text(text, encoding="utf-8")
    return True


GHIDRA_TYPES_TEMPLATE = """#ifndef GHIDRA_TYPES_H
#define GHIDRA_TYPES_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#ifdef _MSC_VER
/* PE 目标（Windows）：用 Windows 头；STRICT 让 SDK 定义 HINSTANCE__ 等
   struct tag，再补 tag→类型别名（Ghidra 把 HINSTANCE__ 当类型名用）。 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef STRICT
#define STRICT
#endif
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <setjmp.h>
#include <wchar.h>
typedef struct HINSTANCE__ HINSTANCE__;
typedef struct HWND__ HWND__;
typedef struct HDC__ HDC__;
typedef struct HKEY__ HKEY__;
typedef struct HMODULE__ HMODULE__;
typedef struct HICON__ HICON__;
typedef struct HCURSOR__ HCURSOR__;
typedef struct HBRUSH__ HBRUSH__;
typedef struct HMENU__ HMENU__;
typedef struct HHOOK__ HHOOK__;
typedef struct HGDIOBJ__ HGDIOBJ__;
typedef struct HBITMAP__ HBITMAP__;
typedef struct HPEN__ HPEN__;
typedef struct HFONT__ HFONT__;
typedef struct HRGN__ HRGN__;
typedef struct HPALETTE__ HPALETTE__;
typedef struct HRSRC__ HRSRC__;
typedef struct HLOCAL__ HLOCAL__;
typedef struct HGLOBAL__ HGLOBAL__;
typedef struct HMONITOR__ HMONITOR__;
typedef struct HKL__ HKL__;
typedef struct HWINSTA__ HWINSTA__;
typedef struct HSTR__ HSTR__;
typedef struct HTASK__ HTASK__;
typedef struct HEVENT__ HEVENT__;
typedef struct HACCEL__ HACCEL__;
typedef struct HCOLORSPACE__ HCOLORSPACE__;
typedef struct HENHMETAFILE__ HENHMETAFILE__;
typedef struct HMETAFILE__ HMETAFILE__;
#else
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <poll.h>
#include <sys/epoll.h>
#include <signal.h>
#include <regex.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <wchar.h>
#include <langinfo.h>
#include <elf.h>
#include <netdb.h>
#include <sys/times.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <netinet/ether.h>
#include <setjmp.h>
#include <glob.h>
#include <sys/msg.h>
#include <arpa/nameser.h>
#endif

typedef long double        longdouble;

typedef unsigned char      undefined;
typedef unsigned char      undefined1;
typedef unsigned short     undefined2;
typedef unsigned int       undefined3;
typedef unsigned int       undefined4;
typedef unsigned long long undefined5;
typedef unsigned long long undefined6;
typedef unsigned long long undefined7;
typedef unsigned long long undefined8;

typedef signed char        sbyte;
typedef unsigned char      byte;
typedef unsigned char      uchar;
typedef unsigned short     word;
typedef unsigned short     ushort;
typedef unsigned int       uint;
typedef unsigned int       dword;
typedef unsigned long      ulong;
typedef unsigned long long ulonglong;
typedef long long          longlong;
typedef unsigned long long qword;
typedef unsigned long long uint7;
typedef int                int3;
typedef unsigned int       uint3;
typedef long long          int5;
typedef unsigned long long uint5;
typedef long long          int6;
typedef unsigned long long uint6;
typedef long long          int7;

typedef undefined8 code();

/* Copy the low bytes of a scalar into a Ghidra-decompiled byte array.
   A function keeps the generated code compatible with both GCC and MSVC. */
static inline void ghidra_copy_scalar(void *dst, undefined8 value, size_t size)
{
    memcpy(dst, &value, size);
}

/* Ghidra 会直接引用 C 库类型名（如 pthread_key_create 的析构函数类型） */
typedef void __destr_function(void *);

/* Ghidra 伪类型：DWARF 的 LEB128 编码值 */
typedef unsigned long long uleb128;
typedef long long          sleb128;

/* 动态链接器的 GOT 伪符号（i386 常见，链接由真实动态链接器提供） */
extern unsigned long __DT_PLTGOT;

/* Ghidra 的扩展宽度伪类型（9/10/12/16 字节，编译用 8 字节近似） */
typedef unsigned long long unkbyte9;
typedef unsigned long long unkbyte10;
typedef unsigned long long unkbyte12;
typedef unsigned long long unkbyte16;
typedef unsigned long long unkuint9;
typedef unsigned long long unkuint10;
typedef unsigned long long unkuint12;
typedef unsigned long long unkuint16;
typedef void *(*__start_routine)(void *);

/* Ghidra 类型库里的 posix_spawn 类型（布局按其成员用法对齐） */
typedef struct { unsigned long __val[16]; } __gh_ghidra_sigset_t;
typedef struct { __gh_ghidra_sigset_t __sd; __gh_ghidra_sigset_t __ss; }
        posix_spawnattr_t;
typedef struct { unsigned long __pad[16]; } posix_spawn_file_actions_t;
typedef struct { unsigned long __pad[8]; } __spawn_action;
typedef struct epoll_event epoll_event;

/* glibc 栈保护符号（公共头未声明；Ghidra 有时多写一个下划线） */
extern unsigned long __stack_chk_guard;
extern void __stack_chk_fail();
#ifndef ___stack_chk_guard
#define ___stack_chk_guard __stack_chk_guard
#endif

/* Ghidra 的 ELF 头类型成员名与 glibc <elf.h> 不同，做别名兼容 */
#ifndef e_ident_magic_str
#define e_ident_magic_str e_ident
#endif
#ifndef e_ident_pad
#define e_ident_pad e_ident
#endif
#ifndef e_ident_class
#define e_ident_class e_ident
#endif

/* glibc / POSIX struct types (Ghidra emits them without the `struct` keyword).
   `timezone` and `sigaction` are deliberately NOT typedef'd here: those
   identifiers are already taken by a glibc global variable and a function
   respectively. They are rewritten to `struct timezone` / `struct sigaction`
   at code-generation time instead. */
typedef struct tm tm;
typedef struct termios termios;
typedef struct in_addr in_addr;
typedef struct utsname utsname;
typedef struct sockaddr sockaddr;
typedef struct timespec timespec;
typedef struct timeval timeval;
typedef struct pollfd pollfd;
typedef struct dirent dirent;
typedef struct servent servent;
typedef struct hostent hostent;
typedef struct addrinfo addrinfo;
typedef struct tms tms;
typedef struct rlimit rlimit;
typedef struct rlimit64 rlimit64;
typedef struct sched_param sched_param;
typedef struct iovec iovec;
typedef struct cmsghdr cmsghdr;
typedef struct msghdr msghdr;
typedef struct ether_addr ether_addr;
typedef struct msqid_ds msqid_ds;
typedef struct __jmp_buf_tag __jmp_buf_tag;

/* Ghidra anonymous union (here: the `sa_handler` member of `struct sigaction`).
   `sa_handler`/`sa_sigaction` are glibc macros expanding to
   `__sigaction_handler.sa_handler`, so we must undef them while declaring the
   union members, then restore them for the accessor expressions in the code. */
#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif
typedef union {
    unsigned long long _dummy;
    struct {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, void *, void *);
    } __sigaction_handler;
} _union_1457;
#define sa_handler __sigaction_handler.sa_handler
#define sa_sigaction __sigaction_handler.sa_sigaction

#ifndef ZEXT816
#define ZEXT816(x) ((unsigned long long)(x) << 0x40)
#endif

/* Ghidra 伪代码拼接运算：CONCATxy(a,b) = a(x 字节) 在前、b(y 字节) 在后，
   结果 x+y 字节。C 里只能用整数类型近似表示（<= 8 字节，3 字节用掩码）。 */
#ifndef CONCAT11
#define CONCAT11(a,b) ((unsigned short)(((unsigned short)(a) << 8) | (unsigned char)(b)))
#endif
#ifndef CONCAT12
#define CONCAT12(a,b) ((unsigned int)(((unsigned int)(a) << 16) | (unsigned short)(b)))
#endif
#ifndef CONCAT13
#define CONCAT13(a,b) ((unsigned int)(((unsigned int)(a) << 24) | ((unsigned int)(b) & 0xffffffu)))
#endif
#ifndef CONCAT14
#define CONCAT14(a,b) ((unsigned long long)(((unsigned long long)(a) << 32) | (unsigned int)(b)))
#endif
#ifndef CONCAT21
#define CONCAT21(a,b) ((unsigned int)(((unsigned int)(a) << 8) | (unsigned char)(b)))
#endif
#ifndef CONCAT22
#define CONCAT22(a,b) ((unsigned int)(((unsigned int)(a) << 16) | (unsigned short)(b)))
#endif
#ifndef CONCAT24
#define CONCAT24(a,b) ((unsigned long long)(((unsigned long long)(a) << 32) | (unsigned int)(b)))
#endif
#ifndef CONCAT31
#define CONCAT31(a,b) ((unsigned int)((((unsigned int)(a) & 0xffffffu) << 8) | (unsigned char)(b)))
#endif
#ifndef CONCAT33
#define CONCAT33(a,b) ((unsigned long long)(((unsigned long long)((unsigned int)(a) & 0xffffffu) << 24) | ((unsigned int)(b) & 0xffffffu)))
#endif
#ifndef CONCAT41
#define CONCAT41(a,b) ((unsigned long long)(((unsigned long long)(a) << 8) | (unsigned char)(b)))
#endif
#ifndef CONCAT42
#define CONCAT42(a,b) ((unsigned long long)(((unsigned long long)(a) << 16) | (unsigned short)(b)))
#endif
#ifndef CONCAT44
#define CONCAT44(a,b) ((unsigned long long)(((unsigned long long)(a) << 32) | (unsigned int)(b)))
#endif
#ifndef CONCAT62
#define CONCAT62(a,b) ((unsigned long long)(((unsigned long long)(a) << 16) | (unsigned short)(b)))
#endif
#ifndef CONCAT71
#define CONCAT71(a,b) ((unsigned long long)(((unsigned long long)(a) << 8) | (unsigned char)(b)))
#endif

#ifndef __isoc99_sscanf
#define __isoc99_sscanf sscanf
#endif

#endif
"""

COMPAT_TEMPLATE = """#ifndef COMPAT_H
#define COMPAT_H

#include "ghidra_types.h"

#ifdef _MSC_VER
typedef struct timespec timespec;

static inline int clock_gettime(int clk_id, struct timespec *tp) {
    (void)clk_id;
    return timespec_get(tp, TIME_UTC) ? 0 : -1;
}

enum {
    _G_ISupper  = 0x0100,
    _G_ISlower  = 0x0200,
    _G_ISalpha  = 0x0400,
    _G_ISdigit  = 0x0800,
    _G_ISxdigit = 0x1000,
    _G_ISspace  = 0x2000,
    _G_ISprint  = 0x4000,
    _G_ISgraph  = 0x8000,
};

static inline unsigned short **__ctype_b_loc(void) {
    static unsigned short table[512];
    static unsigned short *ctab;
    static int init = 0;
    if (!init) {
        for (int i = -128; i < 256; ++i) {
            unsigned short f = 0;
            unsigned char c = (unsigned char)i;
            if (c >= '0' && c <= '9') {
                f |= _G_ISdigit | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'A' && c <= 'F') {
                f |= _G_ISupper | _G_ISalpha | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'a' && c <= 'f') {
                f |= _G_ISlower | _G_ISalpha | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'G' && c <= 'Z') {
                f |= _G_ISupper | _G_ISalpha | _G_ISgraph | _G_ISprint;
            } else if (c >= 'g' && c <= 'z') {
                f |= _G_ISlower | _G_ISalpha | _G_ISgraph | _G_ISprint;
            } else if (c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' || c == '\\f' || c == '\\v') {
                f |= _G_ISspace | _G_ISprint;
            } else if (c >= 0x21 && c <= 0x7E) {
                f |= _G_ISgraph | _G_ISprint;
            }
            table[i + 256] = f;
        }
        ctab = table + 256;
        init = 1;
    }
    return &ctab;
}
#endif

#endif
"""

ENTRY_GLUE = {
    "_start", "entry", "_init", "_fini",
    "register_tm_clones", "deregister_tm_clones", "frame_dummy",
    "__do_global_dtors_aux", "__gmon_start__", "__libc_start_main",
    "_dl_relocate_static_pie", "__ctype_b_loc",
    "__scrt_common_main_seh", "__scrt_common_main",
    "__security_init_cookie", "__security_check_cookie",
    "mainCRTStartup", "WinMainCRTStartup", "wmainCRTStartup",
}


def is_stub(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "halt_baddata" in text or "WARNING: Bad instruction" in text


def should_skip(path):
    name = path.stem
    if name.startswith("_"):
        return True
    if name in ENTRY_GLUE:
        return True
    return is_stub(path)


def _quoted_literal_end(text, start):
    """Return the first position after a C string or character literal."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i = min(i + 2, len(text))
        elif text[i] == quote:
            return i + 1
        else:
            i += 1
    return len(text)


def _strip_block_comments(text):
    """Remove C block comments without treating delimiters in literals as comments."""
    parts = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end == -1 else end
            parts.append(text[i:end])
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                parts.append(text[i:])
                break
            i = end + 2
        elif text[i] in ('"', "'"):
            end = _quoted_literal_end(text, i)
            parts.append(text[i:end])
            i = end
        else:
            parts.append(text[i])
            i += 1
    return "".join(parts)


def _protect_c_literals_and_comments(text):
    """Replace literals and line comments with inert tokens during regex repairs."""
    protected = []
    parts = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end == -1 else end
        elif text[i] in ('"', "'"):
            end = _quoted_literal_end(text, i)
        else:
            parts.append(text[i])
            i += 1
            continue
        value = text[i:end]
        token = "\x01%d%s\x02" % (len(protected), "\n" * value.count("\n"))
        protected.append((token, value))
        parts.append(token)
        i = end
    return "".join(parts), protected


def _transform_c_code(text, transform):
    protected_text, protected = _protect_c_literals_and_comments(text)
    result = transform(protected_text)
    for token, value in protected:
        result = result.replace(token, value)
    return result


def _merge_multiline_signature(text):
    """Join the first function signature through its balanced closing paren."""
    offset = 0
    start = None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped and not stripped.startswith(("//", "#")):
            start = offset + len(line) - len(line.lstrip())
            break
        offset += len(line)
    if start is None:
        return text
    opening = text.find("(", start)
    boundary = min(
        (pos for pos in (text.find("{", start), text.find(";", start)) if pos != -1),
        default=len(text),
    )
    if opening == -1 or opening > boundary:
        return text
    depth = 0
    closing = None
    for pos in range(opening, len(text)):
        if text[pos] == "(":
            depth += 1
        elif text[pos] == ")":
            depth -= 1
            if depth == 0:
                closing = pos
                break
    if closing is None or "\n" not in text[start:closing + 1]:
        return text
    signature = re.sub(r"\s+", " ", text[start:closing + 1].strip())
    return text[:start] + signature + text[closing + 1:]


_CODE_PTR_PARAM_RE = re.compile(r"code\s*\*\s*([A-Za-z_]\w*)")


def _fix_data_ptr_params(params, body):
    """Ghidra 把数据指针参数标成 ``code *p``（函数指针），但函数体里按数据用
    （``p[i]`` / ``(uint)p``）→ 改成 ``undefined1 *p``。原型与定义都要用。"""
    for m in list(_CODE_PTR_PARAM_RE.finditer(params)):
        p = m.group(1)
        used = (re.search(r"\b%s\s*\[" % re.escape(p), body)
                or re.search(
                    r"\(\s*(?:u?int|u?long|uint|ulong|undefined\d*|longlong|"
                    r"ulonglong)\s*\)\s*%s\b" % re.escape(p), body))
        if used:
            params = re.sub(r"code\s*\*\s*%s\b" % re.escape(p),
                            "undefined1 *%s" % p, params)
    return params


def parse_signature(text):
    text = _strip_block_comments(text)
    text = _merge_multiline_signature(text)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        m = re.match(r"^(.*?)\s+([\w.\-]+)\s*\((.*)\)\s*$", stripped)
        if m:
            ret = m.group(1).strip()
            # Ghidra 的「数组指针」抽象声明符 `undefined1 (*) [16]` → `undefined1 *`
            # （返回类型必须规范化：抽象声明符不是合法 C）。
            ret = re.sub(r"\(\s*\*\s*\)\s*\[\s*\d+\s*\]", "*", ret)
            ret = re.sub(r"\s*\[\s*\d+\s*\]", " *", ret)
            ret = _repair_anon_func_types(ret)
            ret = re.sub(r"\s+", " ", ret)
            # 参数里的 `(*param_1) [16]` 是合法 C（且支持 param_1[i][j]），保留不动。
            params = _repair_anon_func_types(m.group(3).strip())
            params = re.sub(r"\s+", " ", params)
            return ret, m.group(2), params
        break
    return None


def _iter_files(decomp_dir, files):
    return sorted(decomp_dir.glob("*.c")) if files is None else list(files)


def collect_functions(decomp_dir, files=None):
    funcs = []
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sig = parse_signature(text)
        if sig is None:
            continue
        funcs.append((sig[0], sig[1], sig[2], path))
    return funcs


def find_dup_names(decomp_dir, files=None):
    """找出同名函数（不同模块的 static 同名函数，反编译后被展平成全局同名）。"""
    counts = {}
    for ret, name, params, path in collect_functions(decomp_dir, files):
        counts[name] = counts.get(name, 0) + 1
    return {n for n, c in counts.items() if c > 1}


def find_static_duplicate_definitions(decomp_dir, files=None):
    """Return duplicate definitions to localize, keeping one linkable owner."""
    definitions = {}
    for ret, name, params, path in collect_functions(decomp_dir, files):
        definitions.setdefault(name, []).append(path)
    localized = {}
    for name, paths in definitions.items():
        if len(paths) < 2:
            continue
        for path in sorted(paths)[1:]:
            localized.setdefault(path, set()).add(name)
    return localized


def find_value_used_voids(decomp_dir, files=None):
    """Names of functions decompiled as void/undefined whose return value is
    actually consumed by a caller (assigned or returned)."""
    ret_by_name = {}
    for ret, name, params, path in collect_functions(decomp_dir, files):
        ret_by_name[name] = ret
    value_used = set()
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # 允许调用前有 cast：`x = (ulong *)FUN_x(...)` 也算使用了返回值
        for m in re.finditer(
                r"(?:=\s*|return\s+)(?:\([^()]*\)\s*)*([A-Za-z_]\w*)\s*\(", text):
            name = m.group(1)
            if ret_by_name.get(name) in ("void", "undefined"):
                value_used.add(name)
    return value_used


_SLICE_SIZE_TYPE = {
    1: "undefined1",
    2: "undefined2",
    4: "undefined4",
    8: "undefined8",
}

# slice 基址可以是成员链/下标：`pStack_360.__sd.__val[0]._4_4_`
_SLICE_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\[[^\[\]\n]*\])*)\._(\d+)_(\d+)_")

# 局部标量声明（Ghidra 顶层局部变量）：`undefined8 local_198;` / `ulong local_188;`。
# slice 语法 `var._o_s_` 作用在「变量值」上，标量要取地址 `&var` 才能按字节访问；
# 数组（`undefined1 auVar10 [16];`）直接用变量名即可。
_SCALAR_DECL_RE = re.compile(
    r"^\s*(?:struct\s+\w+|union\s+\w+|enum\s+\w+|undefined\d*|byte|uchar|"
    r"ushort|uint|ulong|longlong|ulonglong|char|short|int|long|size_t|float|"
    r"double|bool|code)\s+(?:\*+\s*)?([A-Za-z_]\w*)\s*;\s*$",
    re.MULTILINE,
)

# 整段 slice 互相拷贝（SIMD/结构体向量搬运常见）：
#     auVar35._0_12_ = auVar19._0_12_;
# 逐元素类型改写无法表达 >8 字节的 slice，直接落成定长 memcpy 最贴近语义。
_SLICE_COPY_RE = re.compile(
    r"^(?P<ind>[ \t]*)(?P<a>[A-Za-z_]\w*)\._(?P<ao>\d+)_(?P<as>\d+)_\s*=\s*"
    r"(?P<b>[A-Za-z_]\w*)\._(?P<bo>\d+)_(?P<bs>\d+)_\s*;\s*$",
    re.MULTILINE,
)
#     auVar10._10_6_ = 0;   -> memset
_SLICE_ZERO_RE = re.compile(
    r"^(?P<ind>[ \t]*)(?P<a>[A-Za-z_]\w*)\._(?P<ao>\d+)_(?P<as>\d+)_\s*=\s*0\s*;\s*$",
    re.MULTILINE,
)
#     auVar22._0_12_ = auVar18;   （RHS 是局部数组/向量变量）-> memcpy
_SLICE_IDENT_RE = re.compile(
    r"^(?P<ind>[ \t]*)(?P<a>[A-Za-z_]\w*)\._(?P<ao>\d+)_(?P<as>\d+)_\s*=\s*"
    r"(?P<b>[A-Za-z_]\w*)\s*;\s*$",
    re.MULTILINE,
)


_AGG_TYPEDEF_SIMPLE_RE = re.compile(
    r"typedef\s+(?:struct|union)\s+\w+\s+([A-Za-z_]\w*)\s*;")
_AGG_TYPEDEF_BLOCK_RE = re.compile(
    r"typedef\s+(?:struct|union)\s*\{.*?\}\s*([A-Za-z_]\w*)\s*;", re.S)


def _repair_type_aliases(text):
    """Ghidra 恢复出的类型名与系统 typedef 不同名：``sigaltstack`` → ``stack_t``。"""
    text = re.sub(r"\(\s*sigaltstack\s*\*", "(stack_t *", text)
    return re.sub(
        r"(?m)^([ \t]*)sigaltstack(\s+\**\s*[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;)",
        r"\1stack_t\2", text)


_LOCAL_SCALAR_DECL_RE = re.compile(
    r"(?m)^([ \t]*)(undefined\d*|byte|uchar|ushort|uint|ulong|longlong|"
    r"ulonglong|char|short|int|long|size_t|float|double|bool)\s+"
    r"([A-Za-z_]\w*)\s*;")


def _widen_pointer_locals(text):
    """Ghidra 把指针局部声明成了标量（随后 ``x[i]`` 或 ``x = (T *)..``）：
    按用法把声明拓宽成指针。"""
    cands = [(m.group(3), m.group(2)) for m in _LOCAL_SCALAR_DECL_RE.finditer(text)]
    for var, typ in cands:
        if (re.search(r"(?m)^[ \t]*%s\s*=\s*\([^;()]*\*[^;()]*\)" % re.escape(var), text)
                or re.search(r"\b%s\s*\[" % re.escape(var), text)):
            text = re.sub(
                r"(?m)^([ \t]*)%s\s+%s\s*;" % (re.escape(typ), re.escape(var)),
                r"\1%s *%s;" % (typ, var), text)
    return text


def _repair_aggregate_casts(text):
    """Ghidra 对结构体/联合体局部变量做字节访问时写成 ``(char *)local``；
    C 里 struct/union 不能转成指针，必须取地址 ``(char *)&local``。
    数组/指针本身可以直接转，不做改动。"""
    agg = (set(_AGG_TYPEDEF_SIMPLE_RE.findall(GHIDRA_TYPES_TEMPLATE))
           | set(_AGG_TYPEDEF_BLOCK_RE.findall(GHIDRA_TYPES_TEMPLATE)))
    parts = [r"struct\s+\w+", r"union\s+\w+", r"_union_\d+", r"_struct_\d+"]
    if agg:
        parts.insert(0, "|".join(re.escape(n) for n in sorted(agg) if n))
    local_re = re.compile(
        r"^\s*(?:%s)\s+([A-Za-z_]\w*)\s*;\s*$" % "|".join(parts),
        re.MULTILINE)
    names = set(local_re.findall(text))
    if not names:
        return text
    name_alt = "|".join(re.escape(n) for n in sorted(names))
    pat = re.compile(
        r"(\(\s*(?:char|undefined\d*)\s*\*\s*\)\s*)(&?)\b(%s)\b(?!\s*(?:\[|\.|->))"
        % name_alt)

    def repl(m):
        if m.group(2) == "&":
            return m.group(0)
        return m.group(1) + "&" + m.group(3)

    return pat.sub(repl, text)


# Ghidra 类型库里的匿名函数类型 `_func_5014`：C 里没有对应 typedef，
# 统一映射成模板里的函数类型 `code`（`_func_NNNN *` → `code *`）。
_ANON_FUNC_TYPE_RE = re.compile(r"\b_func_\d+\b")


def _repair_anon_func_types(text):
    return _ANON_FUNC_TYPE_RE.sub("code", text)


_CODE_CAST_RE = re.compile(r"\(\s*code\s*\)(?!\s*\*)")
# case 标签里的常量：指针不能作为 case 值（GCC 硬错误），改成整数
# 类型可能是多重指针：case (ulonglong ******)0x0:
_CASE_PTR_RE = re.compile(
    r"(case\s+)\(\s*[A-Za-z_]\w*\s*(?:\*+\s*)+\)\s*"
    r"(0[xX][0-9a-fA-F]+|\d+)")


def _repair_code_casts(text):
    """Ghidra 用 ``(code)0x0`` 表示空函数指针；C 不允许 cast 到函数类型，
    改成 ``(code *)0x0``；若出现 ``case (T *)0x..:`` 则转成整数常量。"""
    text = _CODE_CAST_RE.sub("(code *)", text)
    return _CASE_PTR_RE.sub(r"\1(unsigned long)\2", text)


def _slice_base(var, arrays, scalars):
    if "." in var or "[" in var:
        return "(char *)&(%s)" % var
    # 统一取址：数组取 &arr 与 arr 地址相同，标量/未知标识符也按地址解释，
    # 避免把指针值本身当成字节基址（与 golden 回归口径一致）。
    return "(char *)&%s" % var


def _collect_slice_vars(text, extra_arrays=None):
    arrays = {name for name, _count in _ARRAY_DECL_RE.findall(text)}
    if extra_arrays:
        arrays |= set(extra_arrays)
    scalars = set(_SCALAR_DECL_RE.findall(text)) - arrays
    return arrays, scalars


def _repair_slice_copies(text, arrays, scalars):
    """>8 字节的整段 slice 赋值 -> memcpy/memset（精确长度）。"""

    def copy_repl(m):
        size = int(m.group("as"))
        if size <= 8 or m.group("as") != m.group("bs"):
            return m.group(0)
        return "%smemcpy(%s + %s, %s + %s, %s);" % (
            m.group("ind"), _slice_base(m.group("a"), arrays, scalars),
            m.group("ao"), _slice_base(m.group("b"), arrays, scalars),
            m.group("bo"), size,
        )

    def zero_repl(m):
        size = int(m.group("as"))
        if size <= 8:
            return m.group(0)
        return "%smemset(%s + %s, 0, %s);" % (
            m.group("ind"), _slice_base(m.group("a"), arrays, scalars),
            m.group("ao"), size,
        )

    def ident_repl(m):
        size = int(m.group("as"))
        # 只接受「RHS 是本地数组/向量变量」：标量 RHS 的宽 slice 语义是
        # 零/符号扩展，用 memcpy 会越界读，宁可不改。
        if size <= 8 or m.group("b") not in arrays:
            return m.group(0)
        return "%smemcpy(%s + %s, %s, %s);" % (
            m.group("ind"), _slice_base(m.group("a"), arrays, scalars),
            m.group("ao"), m.group("b"), size,
        )

    text = _SLICE_COPY_RE.sub(copy_repl, text)
    text = _SLICE_ZERO_RE.sub(zero_repl, text)
    return _SLICE_IDENT_RE.sub(ident_repl, text)


# 非 2 的幂尺寸（3/5/6/7）的 slice 写：读-改-写，只改 s 字节，不用会越界的
# 伪类型（undefined7 实际 8 字节）。
_SLICE_ASSIGN_RE = re.compile(
    r"^(?P<ind>[ \t]*)(?P<a>[A-Za-z_]\w*)\._(?P<ao>\d+)_(?P<as>\d+)_\s*=\s*"
    r"(?P<expr>[^;]+);\s*$",
    re.MULTILINE,
)


def _repair_slice_assigns(text, arrays, scalars):
    def repl(m):
        size = int(m.group("as"))
        if size in (1, 2, 4, 8) or not (1 <= size <= 8):
            return m.group(0)
        base = _slice_base(m.group("a"), arrays, scalars)
        mask = (1 << (8 * size)) - 1
        addr = "%s + %s" % (base, m.group("ao"))
        return ("%s*(unsigned long long *)(%s) = "
                "(*(unsigned long long *)(%s) & ~0x%xULL) | "
                "((unsigned long long)(%s) & 0x%xULL);"
                % (m.group("ind"), addr, addr, mask, m.group("expr"), mask))

    return _SLICE_ASSIGN_RE.sub(repl, text)


def _repair_slice_syntax(text, extra_arrays=None, extra_scalars=None):
    arrays, scalars = _collect_slice_vars(text, extra_arrays)
    if extra_scalars:
        scalars |= set(extra_scalars)
    text = _repair_slice_copies(text, arrays, scalars)
    text = _repair_slice_assigns(text, arrays, scalars)

    def repl(m):
        var, off, size = m.group(1), m.group(2), int(m.group(3))
        base = _slice_base(var, arrays, scalars)
        t = _SLICE_SIZE_TYPE.get(size) if size in (1, 2, 4, 8) else None
        if t is not None:
            return "*(%s *)(%s + %s)" % (t, base, off)
        if 1 <= size <= 8:
            mask = (1 << (8 * size)) - 1
            return "(*(unsigned long long *)(%s + %s) & 0x%xULL)" % (
                base, off, mask)
        return m.group(0)

    return _SLICE_RE.sub(repl, text)


_QUALIFIED_NAME_RE = re.compile(r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+\b")


def sanitize_qualified_names(text):
    """Ghidra 跳转表标签 ``switchD_x::caseD_y`` / ``switchD_x::switchdataD_y``
    是 C++ 风格限定名，直接输出会报 ``expected ';' before '::'``。
    统一把 ``::`` 替换成 ``_``，变成合法 C 标识符（配套声明/引用一并生效）。"""
    return _QUALIFIED_NAME_RE.sub(lambda m: m.group(0).replace("::", "_"), text)


# Ghidra 有时把「数组返回类型」单独放一行，函数名在下一行（中间空行）：
#     undefined1  [16]
#
#     bb_simplify_path(char *param_1, ...)
# 这会让下面的签名行解析（要求返回类型+函数名同一行）失效，数组 [N] 也就
# 无法转成指针。这里先把分行合并回同一行。
_SPLIT_ARRAY_RETURN_RE = re.compile(
    r"^([A-Za-z_]\w*\s+\[\s*\d+\s*\])\s*\n\s*\n(\s*[A-Za-z_]\w*\s*\()",
    re.MULTILINE,
)
# Ghidra 也会把「函数名」和「参数列表」拆成两行（中间空行）：
#     undefined1  [16] func_name
#
#               (undefined8 param_1, ...)
_SPLIT_ARRAY_PARAMS_RE = re.compile(
    r"^([A-Za-z_]\w*\s+\[\s*\d+\s*\]\s+[A-Za-z_]\w*)\s*\n\s*\n(\s*\([^();]*\))\s*$",
    re.MULTILINE,
)


def _merge_split_array_return(text):
    text = _SPLIT_ARRAY_RETURN_RE.sub(lambda m: m.group(1) + " " + m.group(2), text)
    text = _SPLIT_ARRAY_PARAMS_RE.sub(lambda m: m.group(1) + m.group(2), text)
    return text


_STACK_REF = re.compile(r"\b(stack0x[0-9a-fA-F]+)\b")


def _repair_stack_refs(text):
    idents = sorted({m.group(1) for m in _STACK_REF.finditer(text)})
    if not idents:
        return text
    decls = "\n".join("  undefined1 %s[8];" % i for i in idents)
    idx = text.find("{")
    if idx == -1:
        return text
    return text[:idx + 1] + "\n" + decls + text[idx + 1:]


# 只把「独占一行的简单调用 + 紧随其后的 return;」改写为 return call(...);
# 参数不允许跨行（[^;\n]），且调用必须以行首缩进开头，避免把 if/for 等
# 跨行结构吞进来（曾产生 `return if (...)` 这类伪代码）。
_CALL_RET = re.compile(
    r"^([ \t]*)((?:\(\s*\*\s*[^()\n]+\)|[A-Za-z_]\w*)\s*\([^;\n]*\))"
    r"\s*;\s*\n[ \t]*return;",
    re.MULTILINE,
)


def _return_last_call(text):
    return _CALL_RET.sub(
        lambda m: "%sreturn %s;" % (m.group(1), m.group(2)), text, count=1)


# Struct tags whose bare name collides with a POSIX function or global
# (stat(), flock(), sigaction(), the `timezone` global, ...). Ghidra emits them
# WITHOUT the `struct` keyword, and they cannot be typedef'd because the bare
# identifier is already taken in the global namespace. They are emitted as
# `struct X` instead.
#
# This set is finite: it is exactly the POSIX structs that share a name with a
# same-named function or global. When a new collision shows up as
#   error: unknown type name 'X'  /  error: 'X' redeclared as different kind
# add it here (and make sure the relevant system header is included in
# GHIDRA_TYPES_TEMPLATE).
_STRUCT_TAG_REWRITES = {
    "passwd": "struct passwd",
    "group": "struct group",
    "stat": "struct stat",
    "stat64": "struct stat64",
    "flock": "struct flock",
    "sigaction": "struct sigaction",
    "timezone": "struct timezone",
    "statfs": "struct statfs",
    "statfs64": "struct statfs64",
    "statvfs": "struct statvfs",
    "statvfs64": "struct statvfs64",
    "dirent": "struct dirent",
    "dirent64": "struct dirent64",
    "sysinfo": "struct sysinfo",
}


def _rewrite_struct_types(s):
    for k, v in _STRUCT_TAG_REWRITES.items():
        s = re.sub(r"(?<!struct )\b%s\b" % re.escape(k), v, s)
    return s


def _repair_struct_casts(text):
    for k in _STRUCT_TAG_REWRITES:
        text = re.sub(r"\(%s\s*\*\)" % re.escape(k), "(struct %s *)" % k, text)
    return text


# Struct tags that are NOT also POSIX function names. These are safe to rewrite
# globally (including local variable declarations like `dirent64 *p;`), unlike
# `stat`/`flock`/`sigaction` where a bare `\bstat\b` would also match `stat()`.
_NON_FUNCTION_STRUCT_TAGS = {
    "dirent", "dirent64", "timezone",
}


def _repair_struct_decls(text):
    for k in _NON_FUNCTION_STRUCT_TAGS:
        text = re.sub(r"(?<!struct )\b%s\b" % re.escape(k), "struct %s" % k, text)
    # passwd/group 是常见标识符（变量/字段名），只在“类型 [*]变量;”声明行改写
    for k in ("passwd", "group"):
        text = re.sub(
            r"(?m)^(\s*)%s(\s+\**\s*[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;)" % k,
            r"\1struct %s\2" % k, text)
    return text


# 函数名冲突的结构体 tag（stat()/sigaction()/flock()/statfs()/statvfs()/sysinfo()），
# 在函数体内的局部声明（`stat local_d0;`）也要改成 `struct stat`，但不能误伤
# 同名函数调用 `stat(...)`。用负向前瞻排除后跟 `(` 的调用。
_CONFLICTING_STRUCT_TAGS = {
    "stat", "stat64", "sigaction", "flock", "statfs", "statfs64",
    "statvfs", "statvfs64", "sysinfo",
}


def _repair_conflicting_struct_decls(text):
    for k in _CONFLICTING_STRUCT_TAGS:
        text = re.sub(
            r"(?<!struct )\b%s\b(?!\s*\()" % re.escape(k),
            "struct %s" % k,
            text,
        )
    return text


_ARRAY_DECL_RE = re.compile(
    r"\b(?:undefined\d*|signed char|unsigned char|char|byte|uchar|short|ushort|"
    r"word|int|uint|long|ulong|dword|qword|longlong|ulonglong|size_t|code)"
    r"\s+(?:\*+\s*)?([A-Za-z_]\w*)\s*\[\s*(0[xX][0-9a-fA-F]+|\d*)\s*\]"
)
_ARRAY_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*([^=][^;]*);\s*$",
                              re.MULTILINE)

_CODE_PTR_DECL_RE = re.compile(r"(?m)^([ \t]*)code(\s*\*\s*)([A-Za-z_]\w*)\s*;")
_ARRAY_LVALUE_RE = re.compile(
    r"\*\(\s*char\s*\(\s*\*\s*\)\s*\[\s*[1-8]\s*\]\s*\)")
_ARRAY_CAST_RE = re.compile(
    r"\(\s*(?:char|undefined1)\s*\[\s*([1-8])\s*\]\s*\)\s*")


def _repair_funcptr_arrays(text):
    """``code *name;`` 被当数组下标使用（局部函数指针表）→ ``code *name[1];``；
    随后的 ``name = ...;`` 由数组赋值规则自动修。"""
    names = [m.group(3) for m in _CODE_PTR_DECL_RE.finditer(text)]
    for name in names:
        if re.search(r"\b%s\s*\[" % re.escape(name), text):
            text = re.sub(
                r"(?m)^([ \t]*)code(\s*\*\s*%s)\s*;" % re.escape(name),
                r"\1code\2[1];", text)
    return text


def _repair_array_casts(text):
    """``(char [8])0x..`` / ``*(char (*)[8])(p) = ..`` 这类数组类型 cast 在 C 中
    非法，按 8 字节整数近似改写。"""
    text = _ARRAY_LVALUE_RE.sub("*(unsigned long long *)", text)
    return _ARRAY_CAST_RE.sub(r"(unsigned long long)", text)


def _repair_array_assignments(text, extra_arrays=None):
    """Ghidra 把数组变量当标量赋值（``arr = expr;``）→ ``*(undefined8 *)arr = expr;``。

    局部数组（``undefined1 auVar8[16];`` 之类的向量返回临时变量）和传入的全局
    数组都适用；``arr[i] = expr;`` 不受影响。
    """
    capacities = {name: "sizeof(%s)" % name for name in (extra_arrays or ())}
    for name, count in _ARRAY_DECL_RE.findall(text):
        # 数组形参会退化为指针，sizeof(name) 不是它的真实大小。
        capacities[name] = "sizeof(%s[0]) * (%s)" % (name, count) if count else None
    if not capacities:
        return text

    def repl(m):
        indent, var, expr = m.group(1), m.group(2), m.group(3)
        capacity = capacities.get(var)
        if capacity:
            size = "(%s) < sizeof(undefined8) ? (%s) : sizeof(undefined8)" % (
                capacity, capacity)
            # 由 helper 求值一次 RHS，规避对齐、strict-aliasing 与 C99 复合字面量要求。
            return "%sghidra_copy_scalar(%s, %s, %s);" % (indent, var, expr, size)
        return m.group(0)

    return _ARRAY_ASSIGN_RE.sub(repl, text)

def _repair_global_names(text, global_names):
    """Ghidra prefixes some data symbols with `_` (e.g. `_bb_common_bufsiz1`);
    map them back to the symbol-table name."""
    if not global_names:
        return text
    for name in sorted(set(re.findall(r"\b_([A-Za-z_][A-Za-z0-9_]*)\b", text))):
        if name in global_names:
            text = re.sub(r"\b_%s\b" % re.escape(name), name, text)
    return text


# glibc-provided globals that Ghidra reconstructs (with wrong types) from the
# statically linked copy; these must NOT be redefined or they clash with libc.
LIBC_GLOBALS = {
    "stdin", "stdout", "stderr", "optarg", "optind", "opterr", "optopt",
    "environ", "__environ", "timezone", "tzname", "daylight",
    "program_invocation_name", "program_invocation_short_name",
    "h_errno", "getdate_err",
}


def repair_source_file(src_path, dst_path, value_used=None, global_names=None,
                       dup_names=None, global_arrays=None):
    if value_used is None:
        value_used = find_value_used_voids(src_path.parent)
    text = src_path.read_text(encoding="utf-8", errors="replace")
    text = _strip_block_comments(text)
    text = _merge_multiline_signature(text)

    def repair_code(code):
        code = sanitize_qualified_names(code)
        code = _merge_split_array_return(code)
        code = _repair_anon_func_types(code)
        code = _repair_code_casts(code)
        code = _repair_slice_syntax(code, extra_arrays=global_arrays)
        code = _repair_stack_refs(code)
        code = _repair_struct_casts(code)
        code = _repair_struct_decls(code)
        code = _repair_conflicting_struct_decls(code)
        code = _repair_aggregate_casts(code)
        code = _repair_type_aliases(code)
        code = _widen_pointer_locals(code)
        code = _repair_funcptr_arrays(code)
        code = _repair_array_casts(code)
        code = _repair_array_assignments(code, extra_arrays=global_arrays)
        return _repair_global_names(code, global_names)

    text = _transform_c_code(text, repair_code)
    lines = text.splitlines()

    name = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        m = re.match(r"^(.*?)\s+([\w.\-]+)\s*\((.*)\)\s*$", stripped)
        if not m:
            break

        ret = m.group(1).strip()
        # 数组指针抽象声明符 `undefined1 (*) [16]` → `undefined1 *`
        # （返回类型必须规范化；参数保留 `(*p) [N]`，与 parse_signature 一致）
        ret = re.sub(r"\(\s*\*\s*\)\s*\[\s*\d+\s*\]", "*", ret)
        ret = re.sub(r"\s*\[\s*\d+\s*\]", " *", ret)
        ret = re.sub(r"\s+", " ", ret)
        ret = _rewrite_struct_types(ret)
        params = _rewrite_struct_types(m.group(3).strip())
        params = _fix_data_ptr_params(params, text)
        name = m.group(2)
        if name in value_used and ret in ("void", "undefined"):
            ret = "undefined8"
        if dup_names and name in dup_names:
            lines[idx] = f"static {ret} {name}({params})"
        else:
            lines[idx] = f"{ret} {name}({params})"
        break

    result = "\n".join(lines) + "\n"
    if name in value_used:
        result = _transform_c_code(result, _return_last_call)
    # 内容不变时不重写，保留旧 mtime，使 make 增量编译只编译真正变化的文件
    if dst_path.exists():
        try:
            if dst_path.read_text(encoding="utf-8", errors="replace") == result:
                return
        except OSError:
            pass
    _write_text_if_changed(dst_path, result)


def write_types(out_path):
    _write_text_if_changed(out_path, GHIDRA_TYPES_TEMPLATE)
    return out_path


def write_compat(out_path):
    _write_text_if_changed(out_path, COMPAT_TEMPLATE)
    return out_path


def write_prototypes(decomp_dir, out_path, files=None, dup_names=None, binary=None):
    value_used = find_value_used_voids(decomp_dir, files)
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef FUNCTION_PROTOTYPES_H",
        "#define FUNCTION_PROTOTYPES_H",
        "",
    ]
    imported = binary.get("imported", set()) if binary is not None else set()
    seen = set()
    for ret, name, params, path in collect_functions(decomp_dir, files):
        if should_skip(path):
            continue
        if name in seen:
            continue
        if name in imported:
            continue  # 动态导入的 libc 函数：声明由系统头提供
        if dup_names and name in dup_names:
            continue  # 同名函数不生成 extern 原型（各自文件内 static）
        seen.add(name)
        if name in value_used and ret in ("void", "undefined"):
            ret = "undefined8"
        ret = _rewrite_struct_types(ret)
        params = _rewrite_struct_types(params)
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        params = _fix_data_ptr_params(params, body)
        psig = f"extern {ret} {name}({params});"
        lines.append(psig)
    lines.append("")
    lines.append("#endif")
    _write_text_if_changed(out_path, "\n".join(lines) + "\n")
    return out_path


SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHF_ALLOC = 0x2
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
STT_OBJECT = 1
STT_FUNC = 2


def parse_elf(path):
    """解析 ELF，支持 ELF32/ELF64 与大小端。字段宽度按 class 取，
    pointer_size 供 globals/数据还原等通用逻辑使用。"""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or len(data) < 52:
        return None
    ei_class = data[4]      # 1=ELF32, 2=ELF64
    ei_data = data[5]       # 1=little, 2=big
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    is64 = ei_class == 2
    ptr = 8 if is64 else 4
    end = "<" if ei_data == 1 else ">"

    def u16(off):
        return struct.unpack_from(end + "H", data, off)[0]

    def u32(off):
        return struct.unpack_from(end + "I", data, off)[0]

    def u64(off):
        return struct.unpack_from(end + "Q", data, off)[0]

    def word(off):
        return u64(off) if is64 else u32(off)

    e_type = u16(0x10)
    e_machine = u16(0x12)
    if is64:
        shoff, shentsize, shnum, shstrndx = u64(0x28), u16(0x3A), u16(0x3C), u16(0x3E)
        phoff, phentsize, phnum = u64(0x20), u16(0x36), u16(0x38)
    else:
        shoff, shentsize, shnum, shstrndx = u32(0x20), u16(0x2E), u16(0x30), u16(0x32)
        phoff, phentsize, phnum = u32(0x1C), u16(0x2A), u16(0x2C)

    shsize = 64 if is64 else 40
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if o + shsize > len(data):
            break
        if is64:
            flags, addr, offset, size = u64(o + 8), u64(o + 16), u64(o + 24), u64(o + 32)
            link, info, align = u32(o + 40), u32(o + 44), u64(o + 48)
        else:
            flags, addr, offset, size = u32(o + 8), u32(o + 12), u32(o + 16), u32(o + 20)
            link, info, align = u32(o + 24), u32(o + 28), u32(o + 32)
        secs.append({
            "name_off": u32(o),
            "type": u32(o + 4),
            "flags": flags,
            "addr": addr,
            "offset": offset,
            "size": size,
            "link": link,
            "info": info,
            "align": align,
        })

    # Program headers (executables / shared objects)
    segments = []
    if e_type in (ET_EXEC, ET_DYN):
        phsize = 56 if is64 else 32
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + phsize > len(data):
                break
            p_type = u32(off)
            if is64:
                p_offset, p_vaddr, p_filesz = u64(off + 8), u64(off + 16), u64(off + 32)
            else:
                p_offset, p_vaddr, p_filesz = u32(off + 4), u32(off + 8), u32(off + 16)
            if p_type == 1:
                segments.append((p_vaddr, p_offset, p_filesz))

    # Relocatable objects have no program headers; Ghidra lays allocatable
    # sections out in order, aligned to their sh_addralign, from image base.
    reloc_layout = []
    if e_type == ET_REL:
        image_base = 0x100000
        va = image_base
        for s in secs:
            if s["type"] not in (SHT_PROGBITS, SHT_NOBITS):
                continue
            if not (s["flags"] & SHF_ALLOC):
                continue
            align = s["align"] or 1
            va = (va + align - 1) & ~(align - 1)
            reloc_layout.append((va, s["offset"], s["size"], s["type"]))
            va += s["size"]

    def va_to_offset(va):
        if e_type in (ET_EXEC, ET_DYN):
            for vaddr, offset, filesz in segments:
                if vaddr <= va < vaddr + filesz:
                    return offset + (va - vaddr)
        else:
            for gva, offset, size, stype in reloc_layout:
                if gva <= va < gva + size:
                    if stype == SHT_NOBITS:
                        return None
                    return offset + (va - gva)
        return None

    # Symbol table
    symtab = next((s for s in secs if s["type"] == SHT_SYMTAB), None)
    strtab = secs[symtab["link"]] if symtab is not None and symtab["link"] < len(secs) else None

    syms = []
    if symtab is not None and strtab is not None:
        entsize = 24 if is64 else 16
        count = symtab["size"] // entsize
        base = symtab["offset"]
        str_base = strtab["offset"]
        for i in range(count):
            o = base + i * entsize
            if o + entsize > len(data):
                break
            st_name = u32(o)
            if is64:
                st_info = data[o + 4]
                st_shndx = u16(o + 6)
                st_value = u64(o + 8)
                st_size = u64(o + 16)
            else:
                st_value = u32(o + 4)
                st_size = u32(o + 8)
                st_info = data[o + 12]
                st_shndx = u16(o + 14)
            nul = data.find(b"\x00", str_base + st_name)
            syms.append({
                "name": data[str_base + st_name:nul].decode("utf-8", "replace"),
                "info": st_info,
                "shndx": st_shndx,
                "value": st_value,
                "size": st_size,
            })

    # 动态导入符号（libc 等）：动态链接时其声明由系统头提供，
    # decompile_helper 不应再生成 prototype/定义（否则与系统头 conflicting）。
    imported = set()
    dynsym = next((s for s in secs if s["type"] == SHT_DYNSYM), None)
    if dynsym is not None and dynsym["link"] < len(secs):
        dstr = secs[dynsym["link"]]
        entsize = 24 if is64 else 16
        count = dynsym["size"] // entsize
        base = dynsym["offset"]
        str_base = dstr["offset"]
        for i in range(count):
            o = base + i * entsize
            if o + entsize > len(data):
                break
            st_name = u32(o)
            st_shndx = u16(o + 6) if is64 else u16(o + 14)
            if st_shndx != 0:  # 只取 UND（导入）
                continue
            nul = data.find(b"\x00", str_base + st_name)
            name = data[str_base + st_name:nul].decode("utf-8", "replace")
            if name:
                imported.add(name)

    # Globals: name -> (file_offset or None, size)
    globals_map = {}
    for sym in syms:
        if (sym["info"] & 0xF) != STT_OBJECT:
            continue
        name = sym["name"]
        if not name or name.startswith("_") or "@" in name or "." in name:
            continue
        shndx = sym["shndx"]
        if shndx == 0 or shndx >= len(secs):
            continue
        sec = secs[shndx]
        if sec["type"] == SHT_NOBITS:
            file_offset = None
        elif e_type == ET_REL:
            file_offset = sec["offset"] + sym["value"]
        else:
            file_offset = va_to_offset(sym["value"])
        globals_map[name] = (file_offset, sym["size"])

    # 规范化符号映射：Ghidra 把符号名里的非标识符字符替换成 "_"（ELF 的
    # `dot.0` → Ghidra 标识符 `dot_0`）。globals_map 跳过了带 "."/"@"/"_"
    # 开头的名字，这里规范化后仍可反查，用于给「被使用但未声明」的常量名
    # （如 `&dot_0`）生成定义。
    norm_syms = {}
    for sym in syms:
        name = sym["name"]
        if not name or (sym["info"] & 0xF) != STT_OBJECT:
            continue
        norm = re.sub(r"[^A-Za-z0-9_]", "_", name)
        if norm in globals_map or norm in norm_syms:
            continue
        shndx = sym["shndx"]
        if shndx == 0 or shndx >= len(secs):
            continue
        sec = secs[shndx]
        if sec["type"] == SHT_NOBITS:
            file_offset = None
        elif e_type == ET_REL:
            file_offset = sec["offset"] + sym["value"]
        else:
            file_offset = va_to_offset(sym["value"])
        norm_syms[norm] = (file_offset, sym["size"])

    # 函数符号的规范化名字集合（Ghidra 常量里也有函数，如 fileAction）
    func_syms = set()
    for sym in syms:
        name = sym["name"]
        if not name or (sym["info"] & 0xF) != STT_FUNC:
            continue
        func_syms.add(re.sub(r"[^A-Za-z0-9_]", "_", name))

    # Resolve pointer relocations (R_X86_64_64) for relocatable objects so that
    # arrays of string pointers can be reconstructed from .data.
    resolve_pointer = None
    if e_type == ET_REL:
        # 绝对地址重定位类型：x86-64 R_X86_64_64=1、i386 R_386_32=1、
        # AArch64 R_AARCH64_ABS64=257、ARM R_ARM_ABS32=2
        abs_type = {0x3E: 1, 0x03: 1, 0xB7: 257, 0x28: 2}.get(e_machine, 1)
        relocs = {}
        for s in secs:
            if s["type"] not in (SHT_RELA, SHT_REL):
                continue
            tgt_sec = s["info"]
            tgt_offset = secs[tgt_sec]["offset"] if tgt_sec < len(secs) else 0
            wid = 8 if is64 else 4
            if s["type"] == SHT_RELA:
                entsize = 24 if is64 else 12
            else:
                entsize = 16 if is64 else 8
            count = s["size"] // entsize
            base = s["offset"]
            for i in range(count):
                o = base + i * entsize
                if o + entsize > len(data):
                    break
                if is64:
                    r_offset = u64(o)
                    r_info = u64(o + 8)
                    r_type = r_info & 0xFFFFFFFF
                    sym_idx = r_info >> 32
                else:
                    r_offset = u32(o)
                    r_info = u32(o + 4)
                    r_type = r_info & 0xFF
                    sym_idx = r_info >> 8
                if r_type != abs_type:
                    continue
                if s["type"] == SHT_RELA:
                    addend = struct.unpack_from(end + ("q" if is64 else "i"),
                                                data, o + (16 if is64 else 8))[0]
                else:
                    loc = tgt_offset + r_offset
                    if loc + wid > len(data):
                        continue
                    addend = struct.unpack_from(end + ("q" if is64 else "i"),
                                                data, loc)[0]
                target = None
                if sym_idx < len(syms):
                    sym = syms[sym_idx]
                    if sym["shndx"] < len(secs):
                        target = secs[sym["shndx"]]["offset"] + sym["value"] + addend
                relocs[tgt_offset + r_offset] = target

        def resolve_pointer(file_offset):
            return relocs.get(file_offset)

    return {
        "kind": "elf",
        "data": data,
        "va_to_offset": va_to_offset,
        "globals": globals_map,
        "norm_syms": norm_syms,
        "func_syms": func_syms,
        "imported": imported,
        "pointer_size": ptr,
        "endian": end,
        "resolve_pointer": resolve_pointer,
    }


def parse_pe(path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None
    coff = pe_off + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        o = sec + i * 40
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        vaddr = struct.unpack_from("<I", data, o + 12)[0]
        rawsize = struct.unpack_from("<I", data, o + 16)[0]
        rawptr = struct.unpack_from("<I", data, o + 20)[0]
        sections.append((vaddr, vsize, rawptr, rawsize))

    def va_to_offset(va):
        rva = va - image_base
        for vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                delta = rva - vaddr
                # 虚拟尾部（vsize > rawsize）在文件里没有对应字节，
                # 不能映射到后续节/overlay 数据上。
                if delta >= rawsize:
                    return None
                return rawptr + delta
        return None

    # 导入表（DataDirectory[1]）：Ghidra 会把 IAT thunk 反编译成与 CRT 同名
    # 的函数（abort/calloc/localeconv...），其定义/原型与系统头冲突，需要像
    # ELF 的 .dynsym UND 一样过滤掉。
    imported = set()
    ptr = 8 if magic == 0x20B else 4
    num_dirs_off = opt + (108 if magic == 0x20B else 92)
    dirs_off = opt + (112 if magic == 0x20B else 96)
    if num_dirs_off + 4 <= len(data):
        num_dirs = struct.unpack_from("<I", data, num_dirs_off)[0]
        if num_dirs > 1 and dirs_off + 16 <= len(data):
            imp_rva = struct.unpack_from("<I", data, dirs_off + 8)[0]
            desc = va_to_offset(image_base + imp_rva) if imp_rva else None
            while desc is not None and desc + 20 <= len(data):
                orig_first = struct.unpack_from("<I", data, desc)[0]
                name_rva = struct.unpack_from("<I", data, desc + 12)[0]
                first = struct.unpack_from("<I", data, desc + 16)[0]
                if not (orig_first or name_rva or first):
                    break
                thunk = orig_first or first
                t = va_to_offset(image_base + thunk) if thunk else None
                while t is not None and t + ptr <= len(data):
                    val = struct.unpack_from("<Q" if ptr == 8 else "<I", data, t)[0]
                    if val == 0:
                        break
                    if not (val >> (ptr * 8 - 1)):  # 按名字导入（非序号）
                        no = va_to_offset(image_base + val)
                        if no is not None and no + 2 <= len(data):
                            end = data.find(b"\x00", no + 2, no + 2 + 256)
                            if end != -1:
                                name = data[no + 2:end].decode("ascii", "replace")
                                if name:
                                    imported.add(name)
                    t += ptr
                desc += 20

    return {
        "kind": "pe",
        "data": data,
        "image_base": image_base,
        "va_to_offset": va_to_offset,
        "globals": {},
        "imported": imported,
        "pointer_size": 8 if magic == 0x20B else 4,
    }


def collect_dat_refs(decomp_dir, files=None):
    addrs = set()
    pattern = re.compile(r"\bDAT_([0-9a-fA-F]+)\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            addrs.add(m.group(1).lower())
    return sorted(addrs, key=lambda s: int(s, 16))


def collect_writable_dat_refs(decomp_dir, files=None):
    """Collect `_DAT_xxxx` addresses. Ghidra names an unnamed *writable* global
    at that address with a leading underscore (usually a field inside a big
    buffer like `bb_common_bufsiz1`). These need a writable variable, not a
    `const` array."""
    addrs = set()
    pattern = re.compile(r"\b_DAT_([0-9a-fA-F]+)\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            addrs.add(m.group(1).lower())
    return sorted(addrs, key=lambda s: int(s, 16))


def collect_used_names(decomp_dir, files=None):
    names = set()
    ident = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in ident.finditer(text):
            names.add(m.group(0))
    return names


def escape_bytes(raw):
    parts = []
    for b in raw:
        if 0x20 <= b <= 0x7E and b not in (0x22, 0x5C):
            parts.append(chr(b))
        else:
            parts.append("\\%03o" % b)
    return "".join(parts)


def read_raw(binary, file_offset, size):
    if file_offset is None or file_offset < 0:
        return None
    if file_offset + size > len(binary["data"]):
        return None
    return binary["data"][file_offset:file_offset + size]


def is_array_usage(name, used_text):
    if re.search(r"\*\s*\([^()]*\*\)\s*\(?\s*" + re.escape(name) + r"\b", used_text):
        return True
    if re.search(r"\b" + re.escape(name) + r"\._\d+_\d+_", used_text):
        return True
    return False


def pointer_array_strings(binary, file_offset, size):
    ptr_size = binary.get("pointer_size", 8)
    if file_offset is None or size % ptr_size != 0:
        return None
    n = size // ptr_size
    strings = []
    for i in range(n):
        off = pointer_target_offset(binary, file_offset + i * ptr_size)
        if off is None or off >= len(binary["data"]):
            return None
        chunk = binary["data"][off:off + 512]
        end = chunk.find(b"\x00")
        raw = chunk if end == -1 else chunk[:end]
        if not (raw and looks_like_string(raw)):
            return None
        strings.append(raw)
    return strings


def collect_global_usage(text):
    """一次扫描全部反编译文本，统计每个标识符的用法次数。

    Ghidra 对全局变量只按「数据段大小」猜类型（size==8 → long、size>8 → 数组），
    忽略了代码里的真实用法。这里统计用法，供 global_info 推断真实类型：
    被 ``*var`` 解引用 → 指针；被 ``var & mask`` 位运算 → 整数。
    """
    usage = {}

    def bump(name, key):
        u = usage.setdefault(
            name, {"deref": 0, "bitop": 0, "index": 0, "assign": 0, "addr": 0,
                   "intlit": 0, "ptrassign": 0, "call": 0})
        u[key] += 1

    # 解引用（*var，不含 *(...)、*var( 调用）
    for m in re.finditer(r"\*\s*([A-Za-z_]\w*)\b", text):
        bump(m.group(1), "deref")
    # 位运算：var 作为左操作数（& | ^ << >>）
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:[&|^]|<<|>>)(?![=&])", text):
        bump(m.group(1), "bitop")
    # 位运算：var 作为右操作数（| ^ << >>，不含 & 以免和取地址混淆）
    for m in re.finditer(r"(?:[|^]|<<|>>)\s*([A-Za-z_]\w*)", text):
        bump(m.group(1), "bitop")
    # 索引 var[
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\[", text):
        bump(m.group(1), "index")
    # 赋值 var =（排除 ==）
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=(?!=)", text):
        bump(m.group(1), "assign")
    # 取地址 &var
    for m in re.finditer(r"&\s*([A-Za-z_]\w*)", text):
        bump(m.group(1), "addr")
    # 赋值为整数字面量（= 0 / = 0x1f）→ 标志/计数器/状态机
    for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*=\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*;", text):
        bump(m.group(1), "intlit")
    # 赋值为取地址/函数地址（= &xxx）→ 指针
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*&", text):
        bump(m.group(1), "ptrassign")
    # 被当函数调用（var(...)）
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        bump(m.group(1), "call")
    return usage


def _unsigned_global_info(binary, name, file_offset, size):
    """Return an exact-width unsigned declaration and its stored value."""
    if size not in (1, 2, 4, 8):
        return None
    raw = read_raw(binary, file_offset, size)
    init = None
    if raw is not None:
        value = int.from_bytes(raw, binary.get("byteorder", "little"), signed=False)
        init = "0x%x" % value
    return ("undefined%d %s" % (size, name), init)


def global_info(binary, name, file_offset, size, used_text, usage=None):
    """Return (ctype, initializer_or_None) for a named global."""
    ptr_size = binary.get("pointer_size", 8)

    if size == ptr_size:
        target = pointer_target_string(binary, file_offset)
        if target is not None:
            return ("char *%s" % name, '"%s"' % escape_bytes(target))

    if size and size % ptr_size == 0:
        strings = pointer_array_strings(binary, file_offset, size)
        if strings is not None:
            body = ", ".join('"%s"' % escape_bytes(s) for s in strings)
            return ("char *%s[%d]" % (name, size // ptr_size), "{%s}" % body)

    # 用法推断（优先于数组误判）：Ghidra 按数据段大小猜类型，slice 语法和指针
    # 强转还会触发 is_array_usage 误判；代码里的真实用法才是判据。
    if usage:
        u = usage.get(name)
        if u:
            # 被解引用 → 指针（`*var` 要求 var 是指针）。deref 优先于 bitop：
            # `*var & mask` 里的 `var &` 是解引用后的值做位运算，var 本身仍是指针。
            if u["deref"] > 0:
                return ("undefined8 *%s" % name, None)
            # 位运算占主导（多于取地址/索引）→ 整数；取地址占主导的保持数组。
            if u["bitop"] > 0 and u["bitop"] > u["addr"] + u["index"]:
                integer = _unsigned_global_info(binary, name, file_offset, size)
                if integer is not None:
                    return integer

    if is_array_usage(name, used_text) or size > ptr_size:
        ctype = "unsigned char %s[0x%x]" % (name, size)
        init = None
        raw = read_raw(binary, file_offset, size)
        if raw is not None:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            init = "{%s}" % body
        return (ctype, init)

    if size == 8:
        return ("long %s" % name, None)
    if size == 4:
        init = None
        if file_offset is not None and file_offset + 4 <= len(binary["data"]):
            init = str(struct.unpack_from("<i", binary["data"], file_offset)[0])
        return ("int %s" % name, init)
    if size == 2:
        return ("short %s" % name, None)
    if size == 1:
        return ("char %s" % name, None)
    return ("unsigned char %s[0x%x]" % (name, size), None)


def looks_like_string(raw):
    for b in raw:
        if b in (0x09, 0x0A, 0x0D):
            continue
        if 0x20 <= b <= 0x7E:
            continue
        if b >= 0x80:
            continue
        return False
    return True


def read_pointer_value(binary, file_offset):
    size = binary.get("pointer_size", 8)
    if file_offset is None or file_offset < 0:
        return None
    if file_offset + size > len(binary["data"]):
        return None

    end = binary.get("endian", "<")
    if size == 4:
        return struct.unpack_from(end + "I", binary["data"], file_offset)[0]
    if size == 8:
        return struct.unpack_from(end + "Q", binary["data"], file_offset)[0]
    return None


def pointer_target_offset(binary, file_offset):
    resolver = binary.get("resolve_pointer")
    if resolver is not None:
        off = resolver(file_offset)
        if off is not None:
            return off
    value = read_pointer_value(binary, file_offset)
    if value is None:
        return None
    return binary["va_to_offset"](value)


def pointer_target_string(binary, file_offset):
    off = pointer_target_offset(binary, file_offset)
    if off is None or off >= len(binary["data"]):
        return None

    chunk = binary["data"][off:off + 512]
    end = chunk.find(b"\x00")
    raw = chunk if end == -1 else chunk[:end]
    if raw and looks_like_string(raw):
        return raw
    return None


def referenced_globals(binary, decomp_dir, files=None):
    used = " ".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in _iter_files(decomp_dir, files)
    )
    usage = collect_global_usage(used)
    used_names = collect_used_names(decomp_dir, files)
    result = []
    for name, (file_offset, size) in sorted(binary["globals"].items()):
        if name not in used_names:
            continue
        if name in LIBC_GLOBALS:
            continue
        ctype, init = global_info(binary, name, file_offset, size, used, usage)
        result.append((name, size, ctype, init))
    return result


def dat_entries(binary, decomp_dir, files=None):
    va_to_offset = binary["va_to_offset"]
    data = binary["data"]
    entries = []
    for hexstr in collect_dat_refs(decomp_dir, files):
        addr = int(hexstr, 16)
        off = va_to_offset(addr)
        if off is None or off >= len(data):
            entries.append((hexstr, False, b""))
            continue
        chunk = data[off:off + 512]
        end = chunk.find(b"\x00")
        raw = chunk if end == -1 else chunk[:end]
        entries.append((hexstr, bool(raw and looks_like_string(raw)), raw))
    return entries


def collect_amp_refs(decomp_dir, files=None):
    """收集可能引用未声明符号的标识符：``&name``（取地址）和 ``name =``
    （赋值形式，Ghidra 的 static/常量名如 ``_SL_`` 常以赋值出现）。"""
    names = set()
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"&\s*([A-Za-z_]\w*)\b", text):
            names.add(m.group(1))
        for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*=(?!=)", text):
            names.add(m.group(1))
    return names


def extra_globals(binary, decomp_dir, files=None):
    """标准 globals 之外、可从符号表反查的常量（Ghidra 常量名如 ``&dot_0``）。

    返回 ``[(name, size, file_offset)]``。
    """
    norm_syms = binary.get("norm_syms", {})
    known = set(binary["globals"]) | LIBC_GLOBALS
    result = []
    for name in sorted(collect_amp_refs(decomp_dir, files)):
        if name in known:
            continue
        sym = norm_syms.get(name)
        if sym is None:
            continue
        result.append((name, sym[1], sym[0]))
    return result


def _global_usage(decomp_dir, files=None):
    used = " ".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in _iter_files(decomp_dir, files)
    )
    return collect_global_usage(used)


def _dat_ctype(name, usage):
    """DAT_*/_DAT_* 的真实类型：按代码用法推断，而不是「可写即指针」。

    - 被解引用 / 被当函数调用 / 赋值为取地址 → 指针
    - 参与位运算 → 整数（`unsigned long`）
    - 被赋值为整数字面量 → 整数（标志/计数器/状态机这类最常见）
    - 仅被取地址/索引 → None（保持 const 数组）
    - 其他赋值 → 指针（保持旧行为，真正 ``x = malloc()`` 之类）
    """
    u = usage.get(name)
    if not u:
        return None
    if u["deref"] > 0 or u["call"] > 0 or u["ptrassign"] > 0:
        return "undefined8 *"
    if u["bitop"] > 0:
        return "unsigned long"
    if u["intlit"] > 0 and u["assign"] > 0:
        return "unsigned long"
    if u["assign"] > 0:
        return "undefined8 *"
    return None


def write_data_defs(binary, decomp_dir, out_path, files=None):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#include \"ghidra_types.h\"",
        "",
    ]

    usage = _global_usage(decomp_dir, files)
    for hexstr, is_str, raw in dat_entries(binary, decomp_dir, files):
        ctype = _dat_ctype("DAT_" + hexstr, usage)
        if ctype == "undefined8 *":
            lines.append("/* DAT_%s: pointer (used as a variable) */" % hexstr)
            lines.append("undefined8 *DAT_%s = 0;" % hexstr)
            lines.append("")
            continue
        if ctype == "unsigned long":
            lines.append("/* DAT_%s: integer (assigned/bitops) */" % hexstr)
            lines.append("unsigned long DAT_%s;" % hexstr)
            lines.append("")
            continue
        if not raw:
            lines.append("/* DAT_%s: cannot map to file */" % hexstr)
            lines.append("const unsigned char DAT_%s[16] = {0};" % hexstr)
        elif is_str:
            lines.append('const char DAT_%s[] = "%s";' % (hexstr, escape_bytes(raw)))
        else:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            lines.append("const unsigned char DAT_%s[] = {%s};" % (hexstr, body))
        lines.append("")

    for name, size, ctype, init in referenced_globals(binary, decomp_dir, files):
        lines.append("/* %s (0x%x bytes) */" % (name, size))
        if init is not None:
            lines.append("%s = %s;" % (ctype, init))
        else:
            lines.append("%s;" % ctype)
        lines.append("")

    for hexstr in collect_writable_dat_refs(decomp_dir, files):
        ctype = _dat_ctype("_DAT_" + hexstr, usage) or "undefined8 *"
        lines.append("/* writable unnamed global at 0x%s */" % hexstr)
        if ctype == "unsigned long":
            lines.append("unsigned long _DAT_%s;" % hexstr)
        else:
            lines.append("undefined8 *_DAT_%s;" % hexstr)
        lines.append("")

    for name, size, file_offset in extra_globals(binary, decomp_dir, files):
        size = size or 16
        raw = read_raw(binary, file_offset, size)
        lines.append("/* %s (%d bytes, resolved via symbol table) */" % (name, size))
        if raw is not None:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            lines.append("char %s[0x%x] = {%s};" % (name, size, body))
        else:
            lines.append("char %s[0x%x];" % (name, size))
        lines.append("")

    _write_text_if_changed(out_path, "\n".join(lines) + "\n")
    return out_path


def write_globals(binary, decomp_dir, out_path, files=None):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef GLOBALS_H",
        "#define GLOBALS_H",
        "",
        "#include \"ghidra_types.h\"",
        "",
    ]
    for name, size, ctype, init in referenced_globals(binary, decomp_dir, files):
        lines.append("/* %s (0x%x bytes) */" % (name, size))
        lines.append("extern %s;" % ctype)
        lines.append("")
    usage = _global_usage(decomp_dir, files)
    for hexstr, is_str, raw in dat_entries(binary, decomp_dir, files):
        dtype = _dat_ctype("DAT_" + hexstr, usage)
        if dtype is not None:
            lines.append("extern %s DAT_%s;" % (dtype, hexstr))
            continue
        ctype = "const char" if is_str else "const unsigned char"
        if is_str:
            size = len(raw) + 1
        elif raw:
            size = len(raw)
        else:
            size = 16
        lines.append("extern %s DAT_%s[%d];" % (ctype, hexstr, size))
    for hexstr in collect_writable_dat_refs(decomp_dir, files):
        dtype = _dat_ctype("_DAT_" + hexstr, usage) or "undefined8 *"
        lines.append("extern %s _DAT_%s;" % (dtype, hexstr))
    for name, size, _ in extra_globals(binary, decomp_dir, files):
        lines.append("extern char %s[0x%x];" % (name, size or 16))
    lines.append("#endif")
    _write_text_if_changed(out_path, "\n".join(lines) + "\n")
    return out_path


def write_makefile(out_dir, c_files, exe_name):
    lines = [
        "CC = gcc",
        "CFLAGS = -std=gnu11 -w -MMD -MP -include ghidra_types.h -include compat.h -include function_prototypes.h -include globals.h -I.",
        "SRCS = %s" % " ".join(c_files),
        "OBJS = $(SRCS:.c=.o)",
        "DEPS = $(OBJS:.o=.d)",
        "LDLIBS = -lm",
        "",
        "%s: $(OBJS)" % exe_name,
        "\t$(CC) -o $@ $(OBJS) $(LDLIBS)",
        "",
        "%.o: %.c",
        "\t$(CC) $(CFLAGS) -c $< -o $@",
        "",
        "-include $(DEPS)",
        "",
        ".PHONY: clean",
        "clean:",
        "\trm -f $(OBJS) $(DEPS) %s" % exe_name,
    ]
    _write_text_if_changed(out_dir / "Makefile", "\n".join(lines) + "\n")


def write_build_ps1(out_dir, c_files, exe_name):
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "Set-Location -LiteralPath $PSScriptRoot",
        "$vcvars = @(",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat',",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Auxiliary/Build/vcvars64.bat',",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Auxiliary/Build/vcvars64.bat'",
        ") | Where-Object { Test-Path $_ } | Select-Object -First 1",
        "if (-not $vcvars) { throw 'vcvars64.bat not found' }",
        "cmd /c \"`\"$vcvars`\" >nul 2>&1 && set\" | ForEach-Object {",
        "  if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path (\"env:\" + $matches[1]) -Value $matches[2] }",
        "}",
        "",
        "New-Item -ItemType Directory -Force -Path obj | Out-Null",
        "$objs = @()",
        "$changed = $false",
        "$files = @(",
        "  " + ", ".join('"%s"' % f for f in c_files),
        ")",
        "foreach ($f in $files) {",
        "  $stem = [IO.Path]::GetFileNameWithoutExtension($f)",
        '  $obj = "obj\\$stem.obj"',
        "  $rebuild = -not (Test-Path $obj)",
        "  if (-not $rebuild) {",
        "    $objTime = (Get-Item $obj).LastWriteTime",
        "    if ($objTime -lt (Get-Item $f).LastWriteTime) { $rebuild = $true }",
        '    foreach ($dep in @("ghidra_types.h","compat.h","globals.h")) {',
        "      if ($objTime -lt (Get-Item $dep).LastWriteTime) { $rebuild = $true }",
        "    }",
        "  }",
        "  if ($rebuild) {",
        '    & cl /nologo /utf-8 /w /c /I. /FI ghidra_types.h /FI compat.h /FI function_prototypes.h /FI globals.h "$f" /Fo"$obj"',
        "    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        "    $changed = $true",
        "  }",
        "  $objs += $obj",
        "}",
        "if ($changed -or -not (Test-Path \"%s\")) {" % exe_name,
        "  & link /nologo /out:%s $objs" % exe_name,
        "  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        '  Write-Host "Built %s"' % exe_name,
        "}",
    ]
    _write_text_if_changed(out_dir / "build.ps1", "\n".join(lines) + "\n")


def parse_map_whitelist(map_path):
    """Extract a self-owned function whitelist from a GNU ld map file.

    Code built with -ffunction-sections gets one `.text.<name>` section per
    function, while precompiled system libraries (libc/libm/libgcc) have no
    per-function sections. Those section names are therefore exactly the set of
    self-owned functions, useful to drop system-library code that was
    statically linked into the binary.
    """
    funcs = set()
    sec_re = re.compile(r"^\.text\.([A-Za-z_][A-Za-z0-9_.]*)$")
    with open(map_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = sec_re.match(line.strip())
            if m:
                funcs.add(m.group(1))
    return funcs


def do_all(binary_path, decomp_dir, out_dir, map_path=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = parse_elf(binary_path) or parse_pe(binary_path)
    if binary is None:
        sys.exit("Unsupported binary format: %s" % binary_path)

    kept = [p for p in sorted(decomp_dir.glob("*.c")) if not should_skip(p)]
    skipped = [p for p in sorted(decomp_dir.glob("*.c")) if should_skip(p)]

    filtered = 0
    if map_path:
        whitelist = parse_map_whitelist(map_path)
        # 用函数名（.c 文件签名里的名字）过滤，而非文件名（同名函数文件名含地址后缀）
        name_by_path = {path: name for _, name, _, path in collect_functions(decomp_dir, kept)}
        kept_before = len(kept)
        kept = [p for p in kept if name_by_path.get(p, p.stem) in whitelist]
        filtered = kept_before - len(kept)

    # 排除动态导入符号（libc 等）的反编译文件：其声明由系统头提供，
    # 若参与编译会与系统头 conflicting（如 fscanf/fdopen/getenv）。
    imported = binary.get("imported", set())
    if imported:
        name_by_path = {path: name for _, name, _, path in collect_functions(decomp_dir, kept)}
        kept = [p for p in kept if name_by_path.get(p, p.stem) not in imported]

    # 清理输出目录里遗留的旧 .c（不在本次 kept 中的），避免上次运行生成、
    # 这次已被过滤的文件残留在目录里（虽不进 Makefile 但污染输出）。
    kept_names = {p.name for p in kept} | {"data_defs.c"}
    for old in out_dir.glob("*.c"):
        if old.name not in kept_names:
            old.unlink()

    write_types(out_dir / "ghidra_types.h")
    write_compat(out_dir / "compat.h")
    dup_names = find_dup_names(decomp_dir, kept)
    localized_duplicates = find_static_duplicate_definitions(decomp_dir, kept)
    write_prototypes(decomp_dir, out_dir / "function_prototypes.h", kept, dup_names, binary)
    write_globals(binary, decomp_dir, out_dir / "globals.h", kept)
    write_data_defs(binary, decomp_dir, out_dir / "data_defs.c", kept)

    value_used = find_value_used_voids(decomp_dir, kept)
    global_names = set(binary["globals"].keys())
    # 数组形式的全局变量（globals.h 里以 name[N] 声明），供数组赋值修复规则使用
    global_arrays = set()
    gh_text = (out_dir / "globals.h").read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"extern\s+\S.*?\s+([A-Za-z_]\w*)\s*\[", gh_text):
        global_arrays.add(m.group(1))
    for p in kept:
        repair_source_file(p, out_dir / p.name, value_used, global_names,
                           localized_duplicates.get(p), global_arrays)

    write_makefile(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")
    write_build_ps1(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")

    print("Output: %s" % out_dir)
    print("  kept functions:    %d" % len(kept))
    print("  skipped stubs:     %d" % len(skipped))
    if filtered:
        print("  filtered syslib:   %d" % filtered)
    print("  ghidra_types.h, compat.h, function_prototypes.h, globals.h, data_defs.c, Makefile, build.ps1")

    bad = []
    for p in kept:
        text = p.read_text(encoding="utf-8", errors="replace")
        if "UNRECOVERED_JUMPTABLE" in text or "Could not recover jumptable" in text:
            bad.append(p.name)
    if bad:
        print("  note: unrecoverable-jumptable functions may need manual signature fixes:")
        for n in bad:
            print("    - %s" % n)
    return out_dir


def main():
    parser = argparse.ArgumentParser(
        description="Make Ghidra decompiler output compilable.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_types = sub.add_parser("types", help="write ghidra_types.h")
    p_types.add_argument("-o", "--output", default="ghidra_types.h")

    p_proto = sub.add_parser("prototypes", help="write function_prototypes.h")
    p_proto.add_argument("decomp_dir")
    p_proto.add_argument("-o", "--output", default="function_prototypes.h")

    p_extract = sub.add_parser("extract", help="write data_defs.c from binary + decomp")
    p_extract.add_argument("binary")
    p_extract.add_argument("decomp_dir")
    p_extract.add_argument("-o", "--output", default="data_defs.c")

    p_globals = sub.add_parser("globals", help="write globals.h extern declarations")
    p_globals.add_argument("binary")
    p_globals.add_argument("decomp_dir")
    p_globals.add_argument("-o", "--output", default="globals.h")

    p_all = sub.add_parser("all", help="generate full buildable project")
    p_all.add_argument("binary")
    p_all.add_argument("decomp_dir")
    p_all.add_argument("-o", "--output-dir", default=None)
    p_all.add_argument("--map", default=None,
                       help="GNU ld map file: keep only self-owned functions "
                            "and drop statically-linked system-library code")

    args = parser.parse_args()

    if args.cmd == "types":
        write_types(Path(args.output))
        print("Wrote %s" % args.output)
    elif args.cmd == "prototypes":
        out = write_prototypes(Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "extract":
        binary = parse_elf(Path(args.binary)) or parse_pe(Path(args.binary))
        if binary is None:
            sys.exit("Unsupported binary format: %s" % args.binary)
        out = write_data_defs(binary, Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "globals":
        binary = parse_elf(Path(args.binary)) or parse_pe(Path(args.binary))
        if binary is None:
            sys.exit("Unsupported binary format: %s" % args.binary)
        out = write_globals(binary, Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "all":
        binary_path = Path(args.binary)
        decomp_dir = Path(args.decomp_dir)
        out_dir = Path(args.output_dir) if args.output_dir else Path(
            "decomp_build"
        ) / ("%s_build" % binary_path.stem)
        do_all(binary_path, decomp_dir, out_dir, map_path=args.map)


if __name__ == "__main__":
    main()
