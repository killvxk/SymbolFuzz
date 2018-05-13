#include <stdio.h>
#include <string.h>
  

 
int main(void)
{
int a =0;
char shellcode[0x200];
a = read(0,shellcode,0x200);
//for(int i = 0 ; i<a ; a++)
//	shellcode[i] -= 0x55;
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
