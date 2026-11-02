// Function: log_message
// Address: 0010002f
// Manually restored fixed fixture: SysV va_list setup in test_complex.o
// saves two GP arguments before printf/vprintf/putchar. Not an automatic repair.
void log_message(int level, const char *format, ...)
{
  va_list arguments;
  va_start(arguments, format);
  printf("[%d] ", level);
  vprintf(format, arguments);
  va_end(arguments);
  putchar(10);
}
