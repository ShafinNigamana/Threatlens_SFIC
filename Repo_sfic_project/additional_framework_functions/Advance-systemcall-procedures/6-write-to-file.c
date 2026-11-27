#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>

int main( void)
{    
	int fd;
	char filename[] = "somefile1.txt";
	char buffer[100] = "Knowledge is the supreme power after almighty.\n";
	// char buffer[100] = "Knowledge is the supreme power after almighty.";  // Notice there is no \n. In this case observe file contents.
	int count;

	fd=open(filename, O_WRONLY|O_CREAT, 0660);
	if(fd < 0) {	perror("Creation error");	exit(1);	}

	count = write(fd,buffer,strlen(buffer));
	printf("Wrote %d characters in the file %s.\n",count,filename);

	close(fd);
}