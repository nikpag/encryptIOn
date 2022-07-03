#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
	pid_t p = fork();

	if (p == 0) {
		char *exec_name = "riddle";
		char *argv[] = {exec_name, NULL};
		char *envp[] = {NULL};

		execve(exec_name, argv, envp);
	}

	sleep(1);
	kill(p, SIGCONT);
	wait(NULL);
}
