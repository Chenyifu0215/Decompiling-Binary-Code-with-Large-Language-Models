// Function: int_to_str
// Address:  00100c66
// Type:     undefined int_to_str(void)
// ============================================================

void int_to_str(uint param_1,undefined1 *param_2,int param_3)

{
  uint local_10;
  int local_c;
  
  local_c = 0;
  local_10 = param_1;
  if ((int)param_1 < 0) {
    local_10 = -param_1;
  }
  if (local_10 == 0) {
    *param_2 = 0x30;
    local_c = 1;
  }
  while ((local_10 != 0 && (local_c < param_3 + -1))) {
    param_2[local_c] = (char)(local_10 % 10) + '0';
    local_10 = local_10 / 10;
    local_c = local_c + 1;
  }
  if (((int)param_1 < 0) && (local_c < param_3 + -1)) {
    param_2[local_c] = 0x2d;
    local_c = local_c + 1;
  }
  param_2[local_c] = 0;
  str_reverse(param_2);
  return;
}

