// main.c 
//gcc -o welcome.exe main.c
#include <stdio.h>
#include <string.h>

int main(void) {
    char name[256];
    printf("Enter your name: ");
    fflush(stdout);
    if (!fgets(name, sizeof(name), stdin)) return 1;
    name[strcspn(name, "\r\n")] = 0;
    printf("Welcome, %s!\n", name);
    fflush(stdout);
    return 0;
}
