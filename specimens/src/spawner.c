/* spawner - forks a child that execs /bin/echo, exercising process tracking. */
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t p = fork();
    if (p == 0) {
        execl("/bin/echo", "echo", "child-ran", (char *)0);
        _exit(127); /* exec failed */
    }
    int status = 0;
    waitpid(p, &status, 0);
    printf("parent done (child pid %d)\n", p);
    return 0;
}
