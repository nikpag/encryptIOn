#include <fcntl.h>
#include <unistd.h>

int main()
{
	int fd1[2], fd2[2];

	pipe(fd1);
	dup2(fd1[0], 33);
	dup2(fd1[1], 34);

	pipe(fd2);
	dup2(fd2[0], 53);
	dup2(fd2[1], 54);

	char *exec_name = "riddle";
	char *argv[] = {exec_name, NULL};
	char *envp[] = {NULL};

	execve(exec_name, argv, envp);
}
