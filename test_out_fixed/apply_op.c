// Function: apply_op
// Address:  00100318
// Type:     int apply_op(int op, int a, int b)
// ============================================================

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int apply_op(int op,int a,int b)

{
  uint uVar1;
  
  switch(op) {
  default:
    uVar1 = 0;
    break;
  case 1:
    uVar1 = b + a;
    break;
  case 2:
    uVar1 = a - b;
    break;
  case 3:
    uVar1 = a * b;
    break;
  case 4:
    if (b == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = a / b;
    }
    break;
  case 5:
    if (b == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = a % b;
    }
    break;
  case 6:
    uVar1 = a & b;
    break;
  case 7:
    uVar1 = a | b;
    break;
  case 8:
    uVar1 = a ^ b;
    break;
  case 9:
    uVar1 = a << ((byte)b & 0x1f);
    break;
  case 10:
    uVar1 = a >> ((byte)b & 0x1f);
  }
  return uVar1;
}

