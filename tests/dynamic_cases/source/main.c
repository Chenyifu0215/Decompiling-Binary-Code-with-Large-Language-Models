/* Deliberately injected off-by-one bug; not a measured Ghidra failure. */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 3;
    if (n < 1 || n > 16) return 7;
    int *values = malloc((size_t)n * sizeof(*values));
    if (!values) return 8;
    for (int i = 0; i <= n; ++i) values[i] = i + 1;
    printf("%d\n", values[n - 1]);
    free(values);
    return 0;
}
