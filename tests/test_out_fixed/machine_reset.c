// Function: machine_reset
// Address:  00100d71
// Type:     undefined machine_reset(void)
// ============================================================

void machine_reset(undefined4 *param_1)

{
  int local_c;
  
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    param_1[(long)local_c + 3] = 0;
  }
  return;
}

