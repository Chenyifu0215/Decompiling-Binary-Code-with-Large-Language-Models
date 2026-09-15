// Function: quick_sort
// Address:  00100abf
// Type:     undefined quick_sort(void)
// ============================================================

void quick_sort(undefined8 param_1,int param_2,int param_3)

{
  int iVar1;
  
  if (param_2 < param_3) {
    iVar1 = partition(param_1,param_2,param_3);
    quick_sort(param_1,param_2,iVar1 + -1);
    quick_sort(param_1,iVar1 + 1,param_3);
  }
  return;
}

