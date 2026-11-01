/* t1_switch.c - 压力样本 1：稠密 switch（跳转表）/ 状态机 / 有符号性 / 128 位乘
 *
 * 目标薄弱点：
 *   - 稠密 switch 在 -O2 下生成跳转表 -> Ghidra UNRECOVERED_JUMPTABLE
 *   - char/short/unsigned 混用 -> Ghidra 符号性推断错误
 *   - __int128 乘法 -> SUB168 类 128 位运算（fix_binary_ops 专项）
 *   - 全局函数指针数组（间接调用）
 * 构建：gcc -O2（默认动态链接）后 strip --strip-all
 */
#include <stdio.h>
#include <string.h>

int g_hits[16];
int g_state = 1;

int op_add(int a, int b) { return a + b; }
int op_sub(int a, int b) { return a - b; }
int op_mul(int a, int b) { return a * b; }
int op_div(int a, int b) { return b ? a / b : -1; }
int op_mod(int a, int b) { return b ? a % b : -1; }
int op_and(int a, int b) { return a & b; }
int op_or(int a, int b)  { return a | b; }
int op_xor(int a, int b) { return a ^ b; }
int op_shl(int a, int b) { return (int)((unsigned)a << (b & 31)); }
int op_shr(int a, int b) { return (int)((unsigned)a >> (b & 31)); }
int op_min(int a, int b) { return a < b ? a : b; }
int op_max(int a, int b) { return a > b ? a : b; }

typedef int (*binop_t)(int, int);
binop_t g_handlers[12] = { op_add, op_sub, op_mul, op_div, op_mod, op_and,
                           op_or, op_xor, op_shl, op_shr, op_min, op_max };

int apply_op(int op, int a, int b)
{
    if (op < 0 || op > 11)
        return -1;
    g_hits[op]++;
    switch (op) {
    case 0: return op_add(a, b);
    case 1: return op_sub(a, b);
    case 2: return op_mul(a, b);
    case 3: return op_div(a, b);
    case 4: return op_mod(a, b);
    case 5: return op_and(a, b);
    case 6: return op_or(a, b);
    case 7: return op_xor(a, b);
    case 8: return op_shl(a, b);
    case 9: return op_shr(a, b);
    case 10: return op_min(a, b);
    default: return op_max(a, b);
    }
}

int fsm_step(char c)
{
    int out = 0;
    switch (g_state) {
    case 0:
        if (c == 'a') { g_state = 1; out = 1; }
        break;
    case 1:
        switch (c) {
        case 'a': g_state = 2; out = 2; break;
        case 'b': g_state = 0; out = 3; break;
        default:  out = 4; break;
        }
        break;
    case 2:
        if (c == 'c') g_state = 3;
        /* fallthrough */
    case 3:
        out = (c == 'd') ? 5 : 6;
        if (c == 'z') g_state = 0;
        break;
    case 4:
        out = -1;
        g_state = 1;
        break;
    default:
        g_state = 0;
        out = -2;
        break;
    }
    return out;
}

int run_fsm(const char *s, int n)
{
    int acc = 0;
    for (int i = 0; i < n; i++)
        acc += fsm_step(s[i]) * (i + 1);
    return acc;
}

short sign_extend(char c) { return (short)c; }
int zero_extend(unsigned char c) { return (int)c; }

int mixed_cmp(signed char a, unsigned char b, short c, unsigned short d)
{
    int acc = 0;
    if (a < 0) acc |= 1;
    if (b > 127) acc |= 2;
    if (c < 0) acc |= 4;
    if (d > 0x7fff) acc |= 8;
    acc += (int)(a + b) + (int)(c + d);
    return acc;
}

unsigned long rotate_mix(unsigned long v, int n)
{
    n &= 63;
    if (n == 0)
        return v;
    return (v << n) | (v >> (64 - n));
}

long bit_mix(long v)
{
    unsigned long u = (unsigned long)v;
    u ^= u << 13;
    u ^= u >> 7;
    u ^= u << 17;
    return (long)u;
}

unsigned long long mul_high(unsigned long long a, unsigned long long b)
{
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    return (unsigned long long)(p >> 32);
}

int dispatch_slot(int i, int x)
{
    if (i < 0 || i >= 12)
        return x;
    return g_handlers[i](x, 3);
}

int main(void)
{
    const char *s = "aabccdzzab";
    int acc = apply_op(0, 3, 4);

    for (int i = 0; i < 12; i++)
        acc += apply_op(i, acc + i, 3);
    acc += run_fsm(s, (int)strlen(s));
    acc += sign_extend((char)0xC3) + zero_extend((unsigned char)0xC3);
    acc += mixed_cmp((signed char)-5, 200, -3, 0x9000);
    acc += (int)rotate_mix(0x123456789abcdef0UL, 13);
    acc += (int)bit_mix(acc);
    acc += (int)mul_high(0x123456789abcdefULL, 0xfedcba987654321ULL);
    for (int i = 0; i < 12; i++)
        acc += dispatch_slot(i, acc + i);
    for (int i = 0; i < 12; i++)
        acc += g_hits[i];

    printf("t1=%d\n", acc);
    return 0;
}
