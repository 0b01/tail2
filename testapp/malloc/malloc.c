#include <stdio.h>
#include <stdlib.h>

int blah();

int main() {
    while(getchar())
    {
        void* a = malloc(42);
        blah();
    }
}

int blah() {
    void* a = malloc(24);
}