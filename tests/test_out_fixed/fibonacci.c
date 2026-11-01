// Function: fibonacci
// Address:  00100422
// Type:     undefined fibonacci(void)
// ============================================================

int fibonacci(int param_1)

{
  int iVar1;
  
  if (1 < param_1) {
    iVar1 = fibonacci(param_1 + -1);
    param_1 = fibonacci(param_1 + -2);
    param_1 = param_1 + iVar1;
  }
  return param_1;
}

