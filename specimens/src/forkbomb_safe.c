/* forkbomb_safe - bounded fork fan-out for process-tracing tests.
 *
 * This resembles the start of a fork bomb, but the child count is fixed and
 * each child exits immediately. It never recurses.
 */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    const int children = 4;

    for (int i = 0; i < children; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(0);
        }
        if (pid < 0) {
            perror("fork");
            break;
        }
    }

    while (wait(NULL) > 0) {
    }

    printf("bounded fork fanout complete (%d children)\n", children);
    return 0;
}
