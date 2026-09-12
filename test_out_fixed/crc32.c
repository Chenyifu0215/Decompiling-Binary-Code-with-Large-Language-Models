// Function: crc32
// Address:  001000f5
// Type:     undefined crc32(void)
// ============================================================

uint crc32(long param_1,ulong param_2)

{
  uint uVar1;
  ulong local_18;
  uint local_c;
  
  local_c = 0xffffffff;
  for (local_18 = 0; local_18 < param_2; local_18 = local_18 + 1) {
    uVar1 = *(uint *)(g_crc_table + (ulong)((*(byte *)(local_18 + param_1) ^ local_c) & 0xf) * 4) ^
            local_c >> 4;
    local_c = *(uint *)(g_crc_table +
                       (ulong)((*(byte *)(local_18 + param_1) >> 4 ^ uVar1) & 0xf) * 4) ^ uVar1 >> 4
    ;
  }
  return ~local_c;
}

