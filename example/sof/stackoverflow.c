#include <stdio.h>
#include <string.h>
  

 
int main(void)
{
char shellcode[0x20];
read(0,shellcode,0x200);
memset(shellcode,0x41,0x200);
printf("%p",shellcode);
//for(int i = 0 ; i<a ; a++)
//	shellcode[i] -= 0x55;
//fprintf(stdout,"Length: %d\n",strlen(shellcode));
//(*(void(*)()) shellcode)();
return 0;
}
