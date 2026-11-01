// Function: main
// Address:  00101021
// Type:     undefined main(void)
// ============================================================

undefined8 main(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  undefined4 local_238;
  undefined4 local_234;
  undefined4 local_230;
  undefined4 local_22c;
  undefined4 local_228;
  undefined1 local_218 [80];
  undefined1 local_1c8 [28];
  int local_1ac;
  uint local_1a8 [67];
  uint local_9c;
  undefined1 local_98 [32];
  uint local_78 [11];
  uint local_4c;
  long local_48;
  int local_3c;
  int local_38;
  int local_34;
  undefined8 local_30;
  int local_24;
  int local_20;
  uint local_1c;
  
  local_78[0] = 0x2a;
  local_78[1] = 7;
  local_78[2] = 0x13;
  local_78[3] = 3;
  local_78[4] = 0xb;
  local_78[5] = 0x38;
  local_78[6] = 0x17;
  local_78[7] = 8;
  local_78[8] = 0x1f;
  local_78[9] = 5;
  local_3c = 10;
  printf("complex test v%d.%d\n",3,7);
  record_add("alpha",1,1);
  record_add(&DAT_00101bc0,2,2);
  record_add("gamma",3,4);
  record_dump();
  local_1c = 0;
  for (local_20 = 0; local_20 < local_3c; local_20 = local_20 + 1) {
    local_1c = local_1c + local_78[local_20];
  }
  printf("sum=%d\n",(ulong)local_1c);
  quick_sort(local_78,0,local_3c + -1);
  printf("sorted:");
  for (local_24 = 0; local_24 < local_3c; local_24 = local_24 + 1) {
    printf(" %d",(ulong)local_78[local_24]);
  }
  putchar(10);
  uVar1 = fibonacci(10);
  printf("fib(10)=%d\n",(ulong)uVar1);
  uVar1 = factorial(6);
  printf("fact(6)=%d\n",(ulong)uVar1);
  uVar1 = gcd(0x30,0x24);
  printf("gcd(48,36)=%d\n",(ulong)uVar1);
  uVar1 = ackermann(2,2);
  printf("ack(2,2)=%d\n",(ulong)uVar1);
  uVar1 = bit_count(0xf0f);
  printf("bits(0xF0F)=%d\n",(ulong)uVar1);
  uVar1 = reverse_bits(0x12345678);
  printf("rev(0x12345678)=0x%X\n",(ulong)uVar1);
  uVar1 = is_power_of_two(0x40);
  printf("pow2(64)=%d\n",(ulong)uVar1);
  int_to_str(0xffffcfc7,local_98,0x20);
  printf("int_to_str(-12345)=%s\n",local_98);
  local_9c = 0;
  iVar2 = str_to_int("-9876",&local_9c);
  if (iVar2 == 0) {
    printf("str_to_int(-9876)=%d\n",(ulong)local_9c);
  }
  uVar1 = crc32("hello world",0xb);
  printf("crc32=%08X\n",(ulong)uVar1);
  uVar1 = apply_op_fn(op_mul,6,7);
  uVar3 = apply_op_fn(op_add,0x14,0x16);
  printf("add_fn=%d mul_fn=%d\n",(ulong)uVar3,(ulong)uVar1);
  local_30 = 0;
  for (local_34 = 0; local_34 < local_3c; local_34 = local_34 + 1) {
    local_30 = bst_insert(local_30,local_78[local_34]);
  }
  local_1ac = 0;
  bst_inorder(local_30,local_1a8,&local_1ac);
  printf("bst_inorder:");
  for (local_38 = 0; local_38 < local_1ac; local_38 = local_38 + 1) {
    printf(" %d",(ulong)local_1a8[local_38]);
  }
  putchar(10);
  local_48 = bst_find(local_30,0x17);
  if (local_48 == 0) {
    pcVar4 = "missing";
  }
  else {
    pcVar4 = "found";
  }
  printf("bst_find(23)=%s\n",pcVar4);
  bst_free(local_30);
  list_init(local_1c8,8);
  list_append(local_1c8,10);
  list_append(local_1c8,0x14);
  list_append(local_1c8,0x1e);
  list_remove(local_1c8,0x14);
  uVar1 = list_sum(local_1c8);
  printf("list_sum=%d\n",(ulong)uVar1);
  local_238 = 1;
  local_234 = 3;
  local_230 = 8;
  local_22c = 9;
  local_228 = 2;
  local_4c = machine_run(local_218,&local_238,5);
  printf("machine_result=%u\n",(ulong)local_4c);
  printf("allocs=%d frees=%d\n",(ulong)g_total_allocations,(ulong)g_total_frees);
  printf("g_error_strings[2]=%s\n",g_error_strings._16_8_);
  printf("g_op_names[OP_MUL]=%s\n",g_op_names._24_8_);
  return 0;
}

