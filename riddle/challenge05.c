#include <fcntl.h>
#include <unistd.h>

int main()
{
	int fd = open("dummy-file-for-ch5", O_CREAT);
	dup2(fd, 99);

	char *exec_name = "riddle";
	char *argv[] = {exec_name, NULL};
	char *envp[] = {NULL};

	execve(exec_name, argv, envp);
}
