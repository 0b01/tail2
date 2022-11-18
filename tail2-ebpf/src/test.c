#include <stddef.h>
#include <stdio.h>
struct tcbhead_t
{
        void      *tcb;
        void     *dtv;
        void      *self;                    /* Pointer to the thread descriptor.  */
};

int main() {
    printf("offset: %ld", offsetof(struct tcbhead_t, self));
}