// Function: record_dump
// Address:  00100fae
// Type:     undefined record_dump(void)
// ============================================================

void record_dump(void)

{
  uint local_c;
  
  for (local_c = 0; (int)local_c < g_record_count; local_c = local_c + 1) {
    printf("record %d: name=%s id=%u flags=0x%X\n",(ulong)local_c,
           *(undefined8 *)(g_records + (long)(int)local_c * 0x10),
           (ulong)*(uint *)(g_records + (long)(int)local_c * 0x10 + 8),
           (ulong)*(uint *)(g_records + (long)(int)local_c * 0x10 + 0xc));
  }
  return;
}

