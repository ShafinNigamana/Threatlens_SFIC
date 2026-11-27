#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>

int main( void)
{    
	int fd;
	char filename[] = "file2.txt";

	fd=creat(filename, 0666);

	if(fd < 0) 
	{
		perror("Creation error");	exit(1);
	}
	printf("File %s created, fd = %d\n",filename,fd);
	close(fd);
}