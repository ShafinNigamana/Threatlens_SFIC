#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>

int main( void)
{    
	int fd;
	char filename[] = "somefile.txt";
	char buffer[100];
	int count;

	fd=open(filename, O_RDONLY);

	if(fd < 0) {	perror("Creation error");	exit(1);	}
	
	count = read(fd,buffer,15); // Fetch 15 characters from the disk-file
	printf("No. of characters read = %d\n",count);
	printf("Buffer = %s\n",buffer);

	close(fd);
}