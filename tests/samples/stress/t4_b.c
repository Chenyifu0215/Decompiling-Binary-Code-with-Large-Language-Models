/* t4_b.c - 样本 4 的 B 单元：读改 A 单元的全局变量，并与 A 单元互调 */
#include "t4_globals.h"

int b_step(int x)
{
    g_counter -= x;
    return g_counter + (int)(g_mask >> 8);
}

int b_fold(const int *v, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++)
        s += v[i] * g_table[(i * 3) & 7] - (int)g_name[i % 12];
    return s;
}

int b_bounce(int x)
{
    if (x <= 0)
        return b_step(1);
    return a_step(x - 1) + b_step(x);
}

int b_lookup(int key)
{
    return a_lookup(key) + g_handler(key, 3);
}
