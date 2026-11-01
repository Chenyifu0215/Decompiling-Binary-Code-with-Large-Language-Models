// Function: bst_free
// Address:  00100676
// Type:     undefined bst_free(void)
// ============================================================

void bst_free(long param_1)

{
  if (param_1 != 0) {
    bst_free(*(undefined8 *)(param_1 + 8));
    bst_free(*(undefined8 *)(param_1 + 0x10));
    xfree(param_1);
  }
  return;
}

