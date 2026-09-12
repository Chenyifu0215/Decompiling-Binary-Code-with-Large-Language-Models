// Function: bst_insert
// Address:  00100521
// Type:     undefined bst_insert(void)
// ============================================================

int * bst_insert(int *param_1,int param_2)

{
  undefined8 uVar1;
  
  if (param_1 == (int *)0x0) {
    param_1 = (int *)node_create(param_2);
  }
  else if (param_2 < *param_1) {
    uVar1 = bst_insert(*(undefined8 *)(param_1 + 2),param_2);
    *(undefined8 *)(param_1 + 2) = uVar1;
  }
  else if (*param_1 < param_2) {
    uVar1 = bst_insert(*(undefined8 *)(param_1 + 4),param_2);
    *(undefined8 *)(param_1 + 4) = uVar1;
  }
  return param_1;
}

