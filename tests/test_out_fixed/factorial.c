// Function: factorial
// Address:  00100461
// Type:     undefined factorial(void)
// ============================================================

int factorial(int param_1)

{
  int iVar1;
  
  if (param_1 < 2) {
    iVar1 = 1;
  }
  else {
    iVar1 = factorial(param_1 + -1);
    iVar1 = iVar1 * param_1;
  }
  return iVar1;
}

