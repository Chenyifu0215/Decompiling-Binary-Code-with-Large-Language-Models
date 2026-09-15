// Function: list_sum
// Address:  00100853
// Type:     undefined list_sum(void)
// ============================================================

int list_sum(undefined8 *param_1)

{
  int *local_18;
  int local_c;
  
  local_c = 0;
  for (local_18 = (int *)*param_1; local_18 != (int *)0x0; local_18 = *(int **)(local_18 + 6)) {
    local_c = local_c + *local_18;
  }
  return local_c;
}

