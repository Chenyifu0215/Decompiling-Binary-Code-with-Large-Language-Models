// Function: record_find
// Address:  00100f5d
// Type:     undefined record_find(void)
// ============================================================

undefined1 * record_find(int param_1)

{
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (g_record_count <= local_c) {
      return (undefined1 *)0x0;
    }
    if (param_1 == *(int *)(g_records + (long)local_c * 0x10 + 8)) break;
    local_c = local_c + 1;
  }
  return g_records + (long)local_c * 0x10;
}

