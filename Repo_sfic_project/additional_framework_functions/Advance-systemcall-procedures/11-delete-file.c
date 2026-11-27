#include<fcntl.h>
#include<stdio.h>
#include<unistd.h>

int main()
{
	int result;
	char filename[] = "/home/joshi/charusat/tmp";
	
	result = unlink(filename);

	printf("File delete result = %d\n",result);

	return 0;
}