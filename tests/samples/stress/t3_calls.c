/* t3_calls.c - 压力样本 3：密集互调 / 递归 / 变参 / 回调
 *
 * 目标薄弱点：
 *   - 一个 hub 函数被 12+ 个函数高频调用（签名错误的放大器）
 *   - 直接递归、互递归、包装链 -> 调用图稠密
 *   - 自定义变参函数（va_list/vsnprintf）-> LLM 签名推断天花板
 *   - qsort 比较器、全局函数指针分发表 -> 间接调用
 *   - 6/8 参数函数 -> fix_argcount 投票压力
 * 构建：gcc -O2（默认动态链接）后 strip --strip-all
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

int mix(int x)
{
    return (x * 31 + 7) ^ (x >> 3);
}

int f1(int x)  { return mix(x) + mix(x + 1); }
int f2(int x)  { return mix(f1(x)) - x; }
int f3(int x)  { return mix(f1(x) + f2(x)); }
int f4(int x)  { return f2(f2(x)) + f3(x); }
int f5(int x)  { return mix(f4(x) ^ f3(x)); }
int f6(int x)  { return f5(x) + f4(x + 1); }
int f7(int x)  { return mix(f6(x)) + mix(f5(x)); }
int f8(int x, int y) { return f7(x + y) - f6(x - y); }
int f9(int x, int y) { return mix(f8(x, y)) ^ f7(x); }
int f10(int x, int y, int z) { return f9(x, y) + f8(y, z) + f7(z); }
int f11(int x, int y, int z) { return mix(f10(x, y, z)) - f9(z, x); }
int f12(int x, int y, int z) { return f11(x, y, z) + f10(z, x, y); }

int is_odd(int n);
int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }
int is_odd(int n)  { return n == 0 ? 0 : is_even(n - 1); }

long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
long fact(int n) { return n < 2 ? 1 : n * fact(n - 1); }

int ack(int m, int n)
{
    if (m == 0) return n + 1;
    if (n == 0) return ack(m - 1, 1);
    return ack(m - 1, ack(m, n - 1));
}

int vsum(int n, ...)
{
    va_list ap;
    int s = 0;
    va_start(ap, n);
    for (int i = 0; i < n; i++)
        s += va_arg(ap, int);
    va_end(ap);
    return s;
}

int vlog_line(const char *tag, const char *fmt, ...)
{
    char buf[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return n + (int)strlen(tag) + (int)buf[0];
}

int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

typedef int (*fn_t)(int);
fn_t g_dispatch[6];

void init_dispatch(void)
{
    g_dispatch[0] = f1;
    g_dispatch[1] = f2;
    g_dispatch[2] = f3;
    g_dispatch[3] = f4;
    g_dispatch[4] = f5;
    g_dispatch[5] = f6;
}

int call_dispatch(int i, int x)
{
    return g_dispatch[i % 6](x);
}

long combine6(int a, int b, int c, int d, int e, int f)
{
    return (long)a + b * c - d * (long)e + f;
}

long combine8(int a, int b, int c, int d, int e, int f, int g, int h)
{
    return combine6(a, b, c, d, e, f) * g - h;
}

int w0(int x) { return x + 1; }
int w1(int x) { return w0(x) * 2; }
int w2(int x) { return w1(x) - w0(x); }
int w3(int x) { return w2(x) ^ w1(x); }
int w4(int x) { return w3(x) + w2(x + 1); }
int w5(int x) { return w4(mix(x)); }
int w6(int x) { return w5(x) + w4(x - 1); }
int w7(int x) { return w6(x) * 3 - w5(x); }

int main(void)
{
    init_dispatch();

    int acc = f12(1, 2, 3);
    for (int i = 0; i < 20; i++)
        acc += f12(i, i + 1, i + 2) % 997;
    acc += (int)fib(12) + (int)fact(10) + ack(2, 3);
    for (int i = 0; i < 10; i++)
        acc += is_even(i) ? i : -i;
    acc += vsum(4, 1, 2, 3, 4);
    acc += vlog_line("T3", "x=%d y=%d", acc, 7);

    int vals[6] = {9, 3, 7, 1, 8, 2};
    qsort(vals, 6, sizeof(int), cmp_int);
    for (int i = 0; i < 6; i++)
        acc += vals[i] * (i + 1);

    for (int i = 0; i < 12; i++)
        acc += call_dispatch(i, i);

    acc += (int)combine6(1, 2, 3, 4, 5, 6);
    acc += (int)combine8(1, 2, 3, 4, 5, 6, 7, 8);
    acc += w7(5) + w0(acc % 7);

    printf("t3=%d\n", acc);
    return 0;
}
