#include<unistd.h>
#include<fcntl.h>
#include<stdlib.h>
#include<stdio.h>
#include<sys/types.h> //required for lseek

int main()
{
	int fd;
	char msg[20];
	int offset,n;
 
 	fd = open("somefile.txt", O_RDONLY); //open file to read
	if(fd<0)
	{
		printf("%s", " Open Error");
	}

	offset = lseek(fd,3,SEEK_SET);//set file cursor at 3 the character starting of the file
	printf("\ncurrent position of file cursor is %d\n",offset);

	n = read(fd,msg,5); // read next 5 characters
	printf("\n%s",msg);

	offset = lseek(fd,0,SEEK_CUR);
	printf("\ncurrent position of file cursor is %d\n",offset);

	offset = lseek(fd,-10,SEEK_END);//set file cursor at 10 the character before end of the file
	printf("\ncurrent position of file cursor is %d\n",offset);
	n = read(fd,msg,5); // read next 5 characters
	printf("\n%s",msg);
}
