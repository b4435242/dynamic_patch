#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char src[100];

void err_handler(){
	printf("This is error handler\n");
	exit(1);
}

void vulnerable_function(int size) {
    char buffer[16];
    printf("Enter copy size:");
    scanf("%d", &size);
    strncpy(buffer, src, size);
    printf("COPY, %s\n", buffer);
}

int main(int argc, char **argv) {
	int size;
	for(int i=0; i<100; i++)
		src[i] = 'A';
   	while(1)
		vulnerable_function(size);
    return 0;
}
