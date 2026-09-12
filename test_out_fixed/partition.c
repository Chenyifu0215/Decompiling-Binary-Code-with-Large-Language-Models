// Function: partition
// Address:  00100983
// Type:     undefined partition(void)
// ============================================================

int partition(long param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_10;
  undefined4 local_c;
  
  iVar1 = *(int *)(param_1 + (long)param_3 * 4);
  local_c = param_2 + -1;
  for (local_10 = param_2; local_10 < param_3; local_10 = local_10 + 1) {
    if (*(int *)(param_1 + (long)local_10 * 4) <= iVar1) {
      local_c = local_c + 1;
      uVar2 = *(undefined4 *)(param_1 + (long)local_c * 4);
      *(undefined4 *)(param_1 + (long)local_c * 4) = *(undefined4 *)(param_1 + (long)local_10 * 4);
      *(undefined4 *)((long)local_10 * 4 + param_1) = uVar2;
    }
  }
  uVar2 = *(undefined4 *)(param_1 + ((long)local_c + 1) * 4);
  *(undefined4 *)(param_1 + ((long)local_c + 1) * 4) = *(undefined4 *)(param_1 + (long)param_3 * 4);
  *(undefined4 *)((long)param_3 * 4 + param_1) = uVar2;
  return local_c + 1;
}

