/* threader - spawns worker threads, exercising the tracer's thread (CLONE_THREAD)
 * handling. The run must complete without deadlocking the multi-process tracer. */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *worker(void *arg) {
    (void)arg;
    ssize_t n = write(1, "t", 1);
    (void)n;
    return NULL;
}

int main(void) {
    pthread_t th[3];
    for (int i = 0; i < 3; i++) {
        pthread_create(&th[i], NULL, worker, NULL);
    }
    for (int i = 0; i < 3; i++) {
        pthread_join(th[i], NULL);
    }
    printf("\nthreads done\n");
    return 0;
}
