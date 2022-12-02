#include <stdio.h>
#include <stdlib.h>

int blah();

int main() {
        void* a = malloc(42);
        blah();
}

int blah() {
    void* a = malloc(24);
}