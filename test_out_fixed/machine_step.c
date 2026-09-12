// Function: machine_step
// Address:  00100dc6
// Type:     undefined machine_step(void)
// ============================================================

undefined8 machine_step(undefined4 *param_1,int param_2,int param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = apply_op(param_2,param_1[1],param_3);
  param_1[1] = iVar1;
  if ((uint)param_1[2] < 0x10) {
    param_1[(ulong)(uint)param_1[2] + 3] = param_2;
  }
  param_1[2] = param_1[2] + 1;
  if ((uint)param_1[2] < 0x3e9) {
    *param_1 = 1;
    uVar2 = 0;
  }
  else {
    *param_1 = 2;
    uVar2 = 0xfffffffd;
  }
  return uVar2;
}

