/* sleeper - sleeps far longer than any sane wallclock limit, to exercise the
 * harness's timeout/auto-kill path. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("sleeping\n");
    fflush(stdout);
    sleep(3600);
    return 0;
}
