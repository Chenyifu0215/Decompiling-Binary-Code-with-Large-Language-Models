#!/bin/sh
# 构建 4 个动态链接 + stripped 压力样本（在 WSL 内运行）
set -e
cd "$(dirname "$0")"

CFLAGS="-O2 -Wall -Wextra"

gcc $CFLAGS -o t1_switch t1_switch.c
gcc $CFLAGS -o t2_types  t2_types.c
gcc $CFLAGS -o t3_calls  t3_calls.c
gcc $CFLAGS -o t4_multi  t4_main.c t4_a.c t4_b.c

strip --strip-all t1_switch t2_types t3_calls t4_multi

echo "--- results ---"
for b in t1_switch t2_types t3_calls t4_multi; do
    ./$b
done
echo "--- file ---"
file t1_switch t2_types t3_calls t4_multi
