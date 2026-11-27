#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#include<sys/types.h>

int main()
{
	int fd1,fd2; //file descriptors
	char c; //holds read char
	int offset; //current offset

	fd1 = open("somefile.txt", O_RDONLY); //open file to read
	if ( fd1<0)
	{
		printf("%s", " Open Error");
	}

	fd2 = open("somefile-reverse.txt", O_WRONLY | O_CREAT, 0660); //open file to write
	if(fd2<0)
	{
		printf("%s", " Open Error");
	}

	offset = lseek(fd1,-1,SEEK_END); //go the end of file
	while (offset>0)
	{
		read(fd1, &c, 1); //read a char
		write(fd2, &c, 1); //write a char

		//go back to spot to the char before the one just read
		lseek(fd1, -2, SEEK_CUR);
		offset--; //track the current offset
	}

	close(fd1);
	close(fd2);
	return 0;
}