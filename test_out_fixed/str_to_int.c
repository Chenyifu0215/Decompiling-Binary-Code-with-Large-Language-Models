// Function: str_to_int
// Address:  00100bb4
// Type:     undefined str_to_int(void)
// ============================================================

undefined8 str_to_int(char *param_1,int *param_2)

{
  undefined8 uVar1;
  char *local_18;
  int local_10;
  int local_c;
  
  local_c = 1;
  local_10 = 0;
  local_18 = param_1;
  if (*param_1 == '-') {
    local_c = -1;
    local_18 = param_1 + 1;
  }
  if (*local_18 == '\0') {
    uVar1 = 0xfffffffc;
  }
  else {
    for (; *local_18 != '\0'; local_18 = local_18 + 1) {
      if ((*local_18 < '0') || ('9' < *local_18)) {
        return 0xfffffffc;
      }
      local_10 = *local_18 + -0x30 + local_10 * 10;
    }
    *param_2 = local_c * local_10;
    uVar1 = 0;
  }
  return uVar1;
}

