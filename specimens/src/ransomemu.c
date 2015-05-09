/* ransomemu - safely emulates ransomware-like file tampering.
 *
 * The specimen only operates in the harness work directory. Tests plant
 * documents/report.txt as a decoy; this binary renames that single file and
 * writes a harmless recovery note instead of touching arbitrary user data.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_text(const char *path, const char *text, int flags, mode_t mode) {
    int fd = open(path, flags, mode);
    if (fd < 0) {
        return;
    }
    ssize_t n = write(fd, text, strlen(text));
    (void)n;
    close(fd);
}

int main(void) {
    (void)mkdir("documents", 0755);

    write_text("README_RECOVER.txt",
               "ContainRE fixture: no real files were encrypted.\n",
               O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (rename("documents/report.txt", "documents/report.txt.locked") != 0) {
        write_text("documents/report.txt.locked",
                   "placeholder for manual runs without a planted decoy\n",
                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }

    write_text("documents/report.txt.locked",
               "locked-placeholder\n",
               O_WRONLY | O_APPEND, 0644);

    printf("ransom emulator done\n");
    return 0;
}
