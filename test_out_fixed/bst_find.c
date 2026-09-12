// Function: bst_find
// Address:  0010059f
// Type:     undefined bst_find(void)
// ============================================================

int * bst_find(int *param_1,int param_2)

{
  int *local_10;
  
  local_10 = param_1;
  while( true ) {
    if (local_10 == (int *)0x0) {
      return (int *)0x0;
    }
    if (param_2 == *local_10) break;
    if (param_2 < *local_10) {
      local_10 = *(int **)(local_10 + 2);
    }
    else {
      local_10 = *(int **)(local_10 + 4);
    }
  }
  return local_10;
}

