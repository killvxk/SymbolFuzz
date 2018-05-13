CFLAGS := -g -m32 -static

simple_test: simple_test.c
	gcc -o simple_test simple_test.c ${CFLAGS} 

atoi: atoi.c
	gcc -o atoi atoi.c ${CFLAGS} 

printf: printf.c
	gcc -o printf printf.c ${CFLAGS} 

strlen: strlen.c
	gcc -o strlen strlen.c ${CFLAGS}

all: 
	make simple_test 
	make atoi
	make printf
	make strlen

clean: 
	rm simple_test
	rm atoi
