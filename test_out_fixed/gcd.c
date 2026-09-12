// Function: gcd
// Address:  00100490
// Type:     undefined gcd(void)
// ============================================================

ulong gcd(uint param_1,int param_2)

{
  ulong uVar1;
  
  if (param_2 == 0) {
    uVar1 = (ulong)param_1;
  }
  else {
    uVar1 = gcd(param_2,(long)(int)param_1 % (long)param_2 & 0xffffffff);
  }
  return uVar1;
}

