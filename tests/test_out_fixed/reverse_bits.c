// Function: reverse_bits
// Address:  001002ae
// Type:     undefined reverse_bits(void)
// ============================================================

uint reverse_bits(uint param_1)

{
  undefined4 local_1c;
  undefined4 local_10;
  undefined4 local_c;
  
  local_c = 0;
  local_1c = param_1;
  for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
    local_c = local_1c & 1 | local_c * 2;
    local_1c = local_1c >> 1;
  }
  return local_c;
}

