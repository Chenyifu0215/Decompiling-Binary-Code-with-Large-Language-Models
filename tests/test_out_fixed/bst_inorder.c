// Function: bst_inorder
// Address:  001005f4
// Type:     undefined bst_inorder(void)
// ============================================================

void bst_inorder(undefined4 *param_1,long param_2,int *param_3)

{
  int iVar1;
  
  if (param_1 != (undefined4 *)0x0) {
    bst_inorder(*(undefined8 *)(param_1 + 2),param_2,param_3);
    iVar1 = *param_3;
    *param_3 = iVar1 + 1;
    *(undefined4 *)((long)iVar1 * 4 + param_2) = *param_1;
    bst_inorder(*(undefined8 *)(param_1 + 4),param_2,param_3);
  }
  return;
}

