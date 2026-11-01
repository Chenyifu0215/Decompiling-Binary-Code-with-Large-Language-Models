/* t2_types.c - 压力样本 2：结构体按值传参/返回（slice）/ union / 位域 / 数组 / 指针算术
 *
 * 目标薄弱点：
 *   - 大于 16 字节的结构体按值传递、按值返回 -> Ghidra slice 语法与隐式返回指针
 *   - union 类型双关、位域打包 -> undefined 类型/移位符号性
 *   - 二维数组、指针转整数（uintptr_t）-> array type / 整数指针混淆
 *   - double/float 与整数混算
 * 构建：gcc -O2（默认动态链接）后 strip --strip-all
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    int   id;
    long  weight;
    char  name[16];
    short flags[3];
    double score;
} Record;

typedef union {
    unsigned long u;
    double d;
    unsigned char b[8];
    float f[2];
} Pun;

typedef struct {
    unsigned a : 3;
    unsigned b : 5;
    signed   c : 7;
    unsigned d : 17;
} Bits;

Record make_record(int id, long w, const char *nm, double sc)
{
    Record r;
    memset(&r, 0, sizeof(r));
    r.id = id;
    r.weight = w;
    r.score = sc;
    strncpy(r.name, nm, sizeof(r.name) - 1);
    r.flags[0] = (short)(id & 0x7f);
    r.flags[1] = (short)(w & 0x7fff);
    r.flags[2] = (short)((id ^ (int)w) & 0x7f);
    return r;
}

Record mutate(Record r, int mode)
{
    switch (mode & 3) {
    case 0: r.weight += r.id; break;
    case 1: r.score *= 1.5; break;
    case 2: r.name[0] = (char)('A' + (r.id % 26)); break;
    default: r.flags[0] ^= 0x5a; break;
    }
    return r;
}

int consume(const Record *r, Record copy)
{
    int acc = r->id * 3 + (int)r->weight;
    acc += (int)copy.score + copy.flags[0] - copy.flags[2];
    acc += (int)strlen(copy.name);
    return acc;
}

double score_all(const Record *arr, int n)
{
    double s = 0.0;
    for (int i = 0; i < n; i++)
        s += arr[i].score + (double)arr[i].weight;
    return s;
}

long pun_mix(long x, double y)
{
    Pun p;
    p.u = (unsigned long)x;
    p.d += y;
    p.b[3] ^= 0x3c;
    return (long)(p.u ^ (unsigned long)(p.f[0] * 2.0f));
}

unsigned bits_pack(int a, int b, int c)
{
    Bits v;
    v.a = (unsigned)a & 7u;
    v.b = (unsigned)b & 31u;
    v.c = (signed)c & 0x3f;
    v.d = ((unsigned)(a ^ b) * 3u) & 0x1ffffu;
    return (unsigned)v.a | ((unsigned)v.b << 3) |
           (((unsigned)v.c & 0x7fu) << 8) | ((unsigned)v.d << 15);
}

void matmul(const int a[4][4], const int b[4][4], int out[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            int s = 0;
            for (int k = 0; k < 4; k++)
                s += a[i][k] * b[k][j];
            out[i][j] = s;
        }
}

long ptr_walk(const void *base, int len)
{
    long acc = 0;
    const unsigned char *p = (const unsigned char *)base;
    for (int i = 0; i < len; i++)
        acc = (acc << 5) ^ (long)p[i];
    return acc;
}

unsigned long id_hash(const void *p)
{
    return (unsigned long)(uintptr_t)p >> 4;
}

int main(void)
{
    Record arr[4];
    arr[0] = make_record(1, 10, "alpha", 1.5);
    arr[1] = make_record(2, 20, "beta", 2.5);
    arr[2] = make_record(3, 30, "gamma", 3.5);
    arr[3] = make_record(4, 40, "delta", 4.5);
    for (int i = 0; i < 4; i++)
        arr[i] = mutate(arr[i], i);

    int acc = 0;
    for (int i = 0; i < 4; i++)
        acc += consume(&arr[i], arr[(i + 1) & 3]);
    acc += (int)score_all(arr, 4);
    acc += (int)pun_mix(0x1122334455667788L, 3.25);
    acc += (int)bits_pack(3, 17, -9);

    int a[4][4], b[4][4], out[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            a[i][j] = i * 4 + j + 1;
            b[i][j] = (i + 1) * (j + 2);
        }
    matmul(a, b, out);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            acc += out[i][j];

    unsigned char blob[32];
    for (int i = 0; i < 32; i++)
        blob[i] = (unsigned char)(i * 7 + 1);
    acc += (int)ptr_walk(blob, (int)sizeof(blob));
    acc += (int)(id_hash(&blob[32]) - id_hash(&blob[0]));

    Record *heap = (Record *)malloc(sizeof(Record) * 2);
    if (heap) {
        heap[0] = make_record(7, 70, "heap", 7.5);
        heap[1] = mutate(heap[0], 2);
        acc += consume(&heap[0], heap[1]);
        free(heap);
    }

    printf("t2=%d\n", acc);
    return 0;
}
