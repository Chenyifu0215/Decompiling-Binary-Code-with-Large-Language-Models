// Function: ackermann
// Address:  001004c2
// Type:     undefined ackermann(void)
// ============================================================

ulong ackermann(int param_1,int param_2)

{
  undefined4 uVar1;
  ulong uVar2;
  
  if (param_1 == 0) {
    uVar2 = (ulong)(param_2 + 1);
  }
  else if (param_2 == 0) {
    uVar2 = ackermann(param_1 + -1,1);
  }
  else {
    uVar1 = ackermann(param_1,param_2 + -1);
    uVar2 = ackermann(param_1 + -1,uVar1);
  }
  return uVar2;
}

