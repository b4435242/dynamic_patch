#include <stdio.h>
#include <stdlib.h>

void err_handler(){
	printf("This is error handler\n");
	exit(1);
}

void vulnerable_function() {
    char buffer[16];
    printf("Enter your name: ");
    gets(buffer);
    printf("Hello, %s!\n", buffer);
}

int main(int argc, char **argv) {
   	while(1)
		vulnerable_function();
    return 0;
}
