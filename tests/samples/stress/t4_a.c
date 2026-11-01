/* t4_a.c - 样本 4 的 A 单元：定义全部全局变量，并与 B 单元互调 */
#include "t4_globals.h"
#include <string.h>

int g_counter = 1;
char g_name[32] = "t4-globals";
long g_mask = 0x00ff00ff00ff00ffL;
int g_table[8] = {2, 3, 5, 7, 11, 13, 17, 19};
int *g_table_ptr = g_table;
Node g_pool[8];
Node *g_head = 0;
const char *g_msgs[4] = {"zero", "one", "two", "three"};
unsigned char g_blob[24] = {1, 2, 3, 4};

int handler_ab(int a, int b)
{
    return a_step(a) + b_step(b);
}

handler_t g_handler = handler_ab;

void init_globals(void)
{
    for (int i = 0; i < 8; i++) {
        g_pool[i].key = i * 3 + 1;
        g_pool[i].val = (long)i * g_mask;
        g_pool[i].next = (i + 1 < 8) ? &g_pool[i + 1] : 0;
    }
    g_head = &g_pool[0];
    strcpy(g_name, "t4-ready");
    for (int i = 0; i < 24; i++)
        g_blob[i] = (unsigned char)(g_blob[i] + i);
}

int a_step(int x)
{
    g_counter += x;
    return g_counter ^ (int)g_mask;
}

int a_fold(const int *v, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++)
        s += v[i] * g_table_ptr[i & 7];
    return s;
}

int a_bounce(int x)
{
    if (x <= 0)
        return g_counter;
    return b_step(x - 1) + a_step(x);
}

int a_lookup(int key)
{
    Node *p = g_head;
    int n = 0;
    while (p) {
        if (p->key == key)
            return (int)(p->val & 0xffff) + n;
        p = p->next;
        n++;
    }
    return -1;
}
