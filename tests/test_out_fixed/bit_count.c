// Function: bit_count
// Address:  00100282
// Type:     undefined bit_count(void)
// ============================================================

int bit_count(uint param_1)

{
  undefined4 local_1c;
  undefined4 local_c;
  
  local_c = 0;
  for (local_1c = param_1; local_1c != 0; local_1c = local_1c & local_1c - 1) {
    local_c = local_c + 1;
  }
  return local_c;
}

