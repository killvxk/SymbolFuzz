#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    char buf[100];
    read(0, buf, 10);
    int a = atoi(buf);
    printf("%d\n", a);
}
