// Function: is_power_of_two
// Address:  001002ec
// Type:     undefined is_power_of_two(void)
// ============================================================

undefined8 is_power_of_two(uint param_1)

{
  undefined8 uVar1;
  
  if ((param_1 == 0) || ((param_1 - 1 & param_1) != 0)) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}

