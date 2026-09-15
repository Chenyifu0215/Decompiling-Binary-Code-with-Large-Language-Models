// Function: str_reverse
// Address:  00100b25
// Type:     undefined str_reverse(void)
// ============================================================

char * str_reverse(char *param_1)

{
  char cVar1;
  size_t sVar2;
  ulong local_10;
  
  sVar2 = strlen(param_1);
  for (local_10 = 0; local_10 < sVar2 >> 1; local_10 = local_10 + 1) {
    cVar1 = param_1[local_10];
    param_1[local_10] = param_1[(sVar2 - local_10) + -1];
    param_1[(sVar2 - local_10) + -1] = cVar1;
  }
  return param_1;
}

