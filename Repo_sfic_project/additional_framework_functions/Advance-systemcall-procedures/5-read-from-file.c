#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>

int main( void)
{    
	int fd;
	char filename[] = "somefile.txt";
	char buffer[100];
	int count,n;

	fd=open(filename, O_RDONLY);

	if(fd < 0) {	perror("Creation error");	exit(1);	}
	
	printf("Enter no. of characters to read from file: ");
	scanf("%d",&n);
	count = read(fd,buffer,n);
	printf("No. of characters read = %d\n",count);
	printf("Buffer = %s\n",buffer);

	close(fd);
}