#include <stdio.h>
#include <string.h>
  

 
int main(void)
{
char shellcode[0x20];
read(0,shellcode,0x20);
memset(shellcode,0x41,300);
return 0;
}
