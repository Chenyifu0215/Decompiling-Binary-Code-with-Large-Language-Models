// Function: xfree
// Address:  001001ef
// Type:     undefined xfree(void)
// ============================================================

void xfree(void *param_1)

{
  if (param_1 != (void *)0x0) {
    free(param_1);
    g_total_frees = g_total_frees + 1;
  }
  return;
}

