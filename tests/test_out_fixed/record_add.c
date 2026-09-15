// Function: record_add
// Address:  00100ef4
// Type:     undefined record_add(void)
// ============================================================

undefined8 record_add(undefined8 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined8 uVar1;
  long lVar2;
  
  if (g_record_count < 0x40) {
    lVar2 = (long)g_record_count * 0x10;
    g_record_count = g_record_count + 1;
    *(undefined8 *)(g_records + lVar2) = param_1;
    *(undefined4 *)(g_records + lVar2 + 8) = param_2;
    *(undefined4 *)(g_records + lVar2 + 0xc) = param_3;
    uVar1 = 0;
  }
  else {
    uVar1 = 0xfffffffd;
  }
  return uVar1;
}

