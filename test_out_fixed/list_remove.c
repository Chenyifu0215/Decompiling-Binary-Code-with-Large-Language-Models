// Function: list_remove
// Address:  001007a2
// Type:     undefined list_remove(void)
// ============================================================

undefined8 list_remove(long *param_1,int param_2)

{
  long lVar1;
  undefined8 uVar2;
  long *local_10;
  
  for (local_10 = param_1; (*local_10 != 0 && (param_2 != *(int *)*local_10));
      local_10 = (long *)(*local_10 + 0x18)) {
  }
  if (*local_10 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    lVar1 = *local_10;
    *local_10 = *(long *)(lVar1 + 0x18);
    if (lVar1 == param_1[1]) {
      param_1[1] = 0;
    }
    xfree(lVar1);
    *(int *)(param_1 + 2) = (int)param_1[2] + -1;
    uVar2 = 0;
  }
  return uVar2;
}

