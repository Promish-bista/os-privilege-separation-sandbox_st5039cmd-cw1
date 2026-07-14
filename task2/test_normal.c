#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("[test_normal] starting, will run for 2 seconds\n");
    fflush(stdout);
    sleep(2);
    printf("[test_normal] finished normally\n");
    return 0;
}
