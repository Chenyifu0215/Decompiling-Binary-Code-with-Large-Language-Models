// Function: log_message
// Address:  0010002f
// Type:     undefined log_message(void)
// ============================================================

void log_message(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                uint param_9,char *param_10,undefined8 param_11,undefined8 param_12,
                undefined8 param_13,undefined8 param_14)

{
  char in_AL;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined1 *local_c8;
  undefined1 *local_c0;
  undefined1 local_b8 [16];
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = param_1;
    local_78 = param_2;
    local_68 = param_3;
    local_58 = param_4;
    local_48 = param_5;
    local_38 = param_6;
    local_28 = param_7;
    local_18 = param_8;
  }
  local_a8 = param_11;
  local_a0 = param_12;
  local_98 = param_13;
  local_90 = param_14;
  printf("[%d] ",(ulong)param_9);
  local_d0 = 0x10;
  local_cc = 0x30;
  local_c8 = &stack0x00000008;
  local_c0 = local_b8;
  vprintf(param_10,&local_d0);
  putchar(10);
  return;
}

