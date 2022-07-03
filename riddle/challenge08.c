#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define GIGA 1073741824
#define NUMFILES 10
int main()
{
	int fd[NUMFILES];
	char *filename[NUMFILES] = {"bf00", "bf01", "bf02", "bf03", "bf04",
				    "bf05", "bf06", "bf07", "bf08", "bf09"};

	for (int i = 0; i < NUMFILES; i++) {
		fd[i] = open(filename[i], O_CREAT | O_RDWR, S_IRWXU);

		lseek(fd[i], GIGA, SEEK_SET);

		write(fd[i], "abcdefghijklmnop", 16);
	}

	char *exec_name = "riddle";
	char *argv[] = {exec_name, NULL};
	char *envp[] = {NULL};
	execve(exec_name, argv, envp);
}
