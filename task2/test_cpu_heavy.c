#include <stdio.h>

int main(void) {
    printf("[test_cpu_heavy] starting infinite CPU-bound loop\n");
    fflush(stdout);
    volatile unsigned long counter = 0;
    while (1) {
        counter++;
    }
    return 0;
}
