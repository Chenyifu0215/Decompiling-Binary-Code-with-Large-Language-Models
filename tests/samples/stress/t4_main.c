/* t4_main.c - 样本 4 主单元：调用 A/B 两单元，触发跨文件原型与全局引用 */
#include "t4_globals.h"
#include <stdio.h>

int main(void)
{
    init_globals();

    int v[6] = {1, 5, 3, 9, 2, 8};
    int acc = a_fold(v, 6) + b_fold(v, 6);

    for (int i = 0; i < 10; i++)
        acc += a_bounce(i) + b_bounce(i);

    acc += a_lookup(3) + a_lookup(9) + b_lookup(4) + b_lookup(42);
    acc += g_handler(4, 5);
    acc += a_step(7) + b_step(7);
    acc += g_msgs[2][0] + (int)g_blob[5];

    printf("t4=%d\n", acc);
    return 0;
}
