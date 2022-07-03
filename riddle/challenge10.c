#include <fcntl.h>
#include <unistd.h>

int main()
{
	int fd = open("secret_number", O_CREAT, S_IRWXU);

	link("secret_number", "secret_number_alias");

	char *exec_name = "riddle";
	char *argv[] = {exec_name, NULL};
	char *envp[] = {NULL};

	execve(exec_name, argv, envp);
}
