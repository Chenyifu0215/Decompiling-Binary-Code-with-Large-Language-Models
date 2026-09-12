// Function: node_create
// Address:  00100224
// Type:     undefined node_create(void)
// ============================================================

undefined4 * node_create(undefined4 param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)xmalloc(0x20);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    *puVar1 = param_1;
    *(undefined8 *)(puVar1 + 2) = 0;
    *(undefined8 *)(puVar1 + 4) = 0;
    *(undefined8 *)(puVar1 + 6) = 0;
  }
  return puVar1;
}

