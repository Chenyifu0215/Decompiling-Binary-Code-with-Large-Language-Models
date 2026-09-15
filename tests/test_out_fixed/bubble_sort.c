// Function: bubble_sort
// Address:  00100894
// Type:     undefined bubble_sort(void)
// ============================================================

void bubble_sort(long param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  
  for (local_c = 0; local_c < param_2 + -1; local_c = local_c + 1) {
    for (local_10 = 0; local_10 < (param_2 - local_c) + -1; local_10 = local_10 + 1) {
      if (*(int *)(param_1 + ((long)local_10 + 1) * 4) < *(int *)(param_1 + (long)local_10 * 4)) {
        uVar1 = *(undefined4 *)(param_1 + (long)local_10 * 4);
        *(undefined4 *)(param_1 + (long)local_10 * 4) =
             *(undefined4 *)(param_1 + ((long)local_10 + 1) * 4);
        *(undefined4 *)(((long)local_10 + 1) * 4 + param_1) = uVar1;
      }
    }
  }
  return;
}

