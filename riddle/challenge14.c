#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
	int fd = open("/proc/sys/kernel/ns_last_pid", O_RDWR);

	write(fd, "32766", 5);

	if (fork() == 0) {
		char *execname = "riddle";
		char *argv[] = {execname, NULL};
		char *envp[] = {NULL};
		execve(execname, argv, envp);
	}
}
