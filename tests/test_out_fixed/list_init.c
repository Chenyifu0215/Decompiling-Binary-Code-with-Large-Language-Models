// Function: list_init
// Address:  001006be
// Type:     undefined list_init(void)
// ============================================================

void list_init(undefined8 *param_1,undefined4 param_2)

{
  *param_1 = 0;
  param_1[1] = 0;
  *(undefined4 *)(param_1 + 2) = 0;
  *(undefined4 *)((long)param_1 + 0x14) = param_2;
  return;
}

