#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
	int fd = open(".hello_there", O_RDWR);
	ftruncate(fd, 32768);
}
