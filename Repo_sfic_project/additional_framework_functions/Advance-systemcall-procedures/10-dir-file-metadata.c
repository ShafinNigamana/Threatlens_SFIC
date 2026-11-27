#include<sys/types.h>
#include<sys/stat.h>
#include<dirent.h>
#include<stdio.h>
#include<stdlib.h>

void listDir(char *dirName)
{
	DIR* dir;
	struct dirent *dirEntry;
	struct stat inode;
	char name[1000];
	dir = opendir(dirName);
	if (dir == 0) { perror ("Eroare deschidere fisier"); exit(1); }

	while ((dirEntry=readdir(dir)) != 0) 
	{
		sprintf(name,"%s/%s",dirName,dirEntry->d_name); 
		lstat (name, &inode);
		// test the type of file
		if (S_ISDIR(inode.st_mode))
			printf("dir ");
		else if (S_ISREG(inode.st_mode))
			printf ("fil ");
		else
			if (S_ISLNK(inode.st_mode))
				printf ("lnk ");
		printf(" %s\n", dirEntry->d_name);
    }
}

int main(int argc, char **argv)
{
	if (argc != 2) 
	{
		printf ("USAGE: %s nume_dir\n", argv[0]);
		exit(0);
	}
    listDir(argv[1]);
}