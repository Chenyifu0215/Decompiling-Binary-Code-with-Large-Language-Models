// Function: xmalloc
// Address:  00100191
// Type:     undefined xmalloc(void)
// ============================================================

void * xmalloc(size_t param_1)

{
  void *pvVar1;
  
  pvVar1 = malloc(param_1);
  if (pvVar1 == (void *)0x0) {
    log_message(2,"allocation of %zu bytes failed",param_1);
    pvVar1 = (void *)0x0;
  }
  else {
    g_total_allocations = g_total_allocations + 1;
  }
  return pvVar1;
}

