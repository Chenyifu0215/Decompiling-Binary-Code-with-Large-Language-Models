// Function: machine_run
// Address:  00100e5e
// Type:     undefined machine_run(void)
// ============================================================

undefined4 machine_run(long param_1,long param_2,ulong param_3)

{
  undefined4 uVar1;
  int iVar2;
  ulong local_10;
  
  machine_reset(param_1);
  local_10 = 0;
  do {
    if (param_3 <= local_10) {
LAB_00100eeb:
      return *(undefined4 *)(param_1 + 4);
    }
    uVar1 = next_rand();
    iVar2 = machine_step(param_1,*(undefined4 *)(param_2 + local_10 * 4),uVar1);
    if (iVar2 != 0) {
      log_message(1,"machine fault at step %zu",local_10);
      goto LAB_00100eeb;
    }
    local_10 = local_10 + 1;
  } while( true );
}

