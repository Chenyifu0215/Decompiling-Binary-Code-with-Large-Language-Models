// Function: vprintf
// Address:  00103008
// Type:     int vprintf(char * __format, __gnuc_va_list __arg)
// ============================================================

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int vprintf(char *__format,__gnuc_va_list __arg)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

