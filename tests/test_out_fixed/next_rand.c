// Function: next_rand
// Address:  00100000
// Type:     undefined next_rand(void)
// ============================================================

uint next_rand(void)

{
  g_seed = g_seed * 0x41c64e6d + 0x3039;
  return g_seed >> 0x10 & 0x7fff;
}

