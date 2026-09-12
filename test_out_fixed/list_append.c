// Function: list_append
// Address:  001006fc
// Type:     undefined list_append(void)
// ============================================================

undefined8 list_append(undefined8 *param_1,undefined4 param_2)

{
  undefined8 uVar1;
  long lVar2;
  
  if (*(int *)(param_1 + 2) < *(int *)((long)param_1 + 0x14)) {
    lVar2 = node_create(param_2);
    if (lVar2 == 0) {
      uVar1 = 0xfffffffe;
    }
    else {
      if (param_1[1] == 0) {
        param_1[1] = lVar2;
        *param_1 = param_1[1];
      }
      else {
        *(long *)(param_1[1] + 0x18) = lVar2;
        param_1[1] = lVar2;
      }
      *(int *)(param_1 + 2) = *(int *)(param_1 + 2) + 1;
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0xfffffffd;
  }
  return uVar1;
}

