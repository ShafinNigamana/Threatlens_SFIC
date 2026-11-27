#include<fcntl.h>
#include<stdio.h>
#include<unistd.h>

int main()
{
	int fd1,fd2;
	fd1 = open("file1.txt",O_RDONLY);
	printf("%d\n",fd1);

	fd2 = open("file1.txt",O_RDONLY);
	printf("%d\n",fd2);

	close(fd1);
	close(fd2);
}