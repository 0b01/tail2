#include <stddef.h>
#include <stdio.h>
struct tcbhead_t
{
        void      *tcb;
        void     *dtv;
        void      *self;                    /* Pointer to the thread descriptor.  */
        int 	multiple_threads;
};

int main() {
    printf("offset: %ld", offsetof(struct tcbhead_t, multiple_threads));
}