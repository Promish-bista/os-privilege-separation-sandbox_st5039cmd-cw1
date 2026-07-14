#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("[test_infinite] starting, will run forever\n");
    fflush(stdout);
    while (1) {
        sleep(1);
    }
    return 0;
}
