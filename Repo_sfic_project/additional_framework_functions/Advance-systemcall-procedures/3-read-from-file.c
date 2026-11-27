#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>

int main( void)
{    
	int fd;
	char filename[] = "somefile.txt";
	char buffer[100];

	fd=open(filename, O_RDONLY);
	if(fd < 0) {	perror("Creation error");	exit(1);	}
	
	read(fd,buffer,10);	// Fetch 10 characters from the disk-file
	printf("Buffer = %s\n",buffer);

	close(fd);
}