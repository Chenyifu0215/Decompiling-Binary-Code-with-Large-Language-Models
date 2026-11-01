/* t4_globals.h - 压力样本 4：跨 3 个编译单元的全局变量与互调
 *
 * 目标薄弱点：
 *   - 全局数组 / 指针 / 指针指向数组 / 全局结构体数组 / 函数指针全局变量
 *     -> decompile_helper 的 globals.h 启发式类型推断
 *   - const 字符串指针数组 -> DAT_* 与字符串还原
 *   - 三文件互调（a<->b 双向调用）-> 跨文件原型、同名符号
 *   - 全局可写变量被赋值 -> const 推断错误
 * 构建：gcc -O2（默认动态链接）后 strip --strip-all
 */
#ifndef T4_GLOBALS_H
#define T4_GLOBALS_H

typedef struct Node {
    int key;
    long val;
    struct Node *next;
} Node;

typedef int (*handler_t)(int, int);

extern int g_counter;
extern char g_name[32];
extern long g_mask;
extern int g_table[8];
extern int *g_table_ptr;
extern Node g_pool[8];
extern Node *g_head;
extern const char *g_msgs[4];
extern handler_t g_handler;
extern unsigned char g_blob[24];

void init_globals(void);
int a_step(int x);
int a_fold(const int *v, int n);
int a_bounce(int x);
int a_lookup(int key);
int b_step(int x);
int b_fold(const int *v, int n);
int b_bounce(int x);
int b_lookup(int key);

#endif
