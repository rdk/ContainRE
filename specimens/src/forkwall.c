/* forkwall - spawn threads until the cgroup pids ceiling refuses one.
 *
 * Deliberately *survives* hitting the wall: it reports the refusal on stdout and
 * exits 0, exactly like a real workload whose helper failed to fork and which
 * recorded that as an ordinary error. That is the shape of failure this
 * specimen exists to reproduce - a run that looks successful from the outside
 * while the kernel was refusing it resources.
 */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

/* Enough to breach any sane test ceiling, small enough that running this by
 * hand on a host without one costs nothing. */
#define MAX_THREADS 256

static void *park(void *arg) {
    (void)arg;
    sleep(30);
    return NULL;
}

int main(void) {
    pthread_t t;
    int made = 0, refused = 0;

    for (int i = 0; i < MAX_THREADS; i++) {
        if (pthread_create(&t, NULL, park, NULL) != 0) {
            refused = 1;
            break;
        }
        made++;
    }

    printf("forkwall: created %d threads, refused=%d\n", made, refused);
    fflush(stdout);

    /* Keep running for a moment after the refusal, as a real workload does: it
     * logs the failed helper and carries on with the next chunk. This is also
     * what makes the breach observable - the counters are sampled from outside,
     * and a container that vanishes in the same instant it breaches leaves
     * nothing to read. */
    sleep(3);
    return 0; /* success, despite the wall - that is the point */
}
