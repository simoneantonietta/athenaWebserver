#include<stdio.h>
#include <stdlib.h>
#include <sys/stat.h>


int main()
{
	/*FILE * fp = fopen("serverroot/index.html","r");
	if(fp == NULL)
	{
		printf("Error opening file\n");
		return 1;
	}*/
	char filename[]="serverroot/favicon.ico";
	char *buffer, *p;
	struct stat buf;
    int bytes_read, bytes_remaining, total_bytes = 0;
	        
        // Get the file size
    if (stat(filename, &buf) == -1) {
	       return NULL;
	}
	                            
	// Make sure it's a regular file
	if (!(buf.st_mode & S_IFREG)) {
	       return NULL;
	}
	                                                
	// Open the file for reading
	FILE *fp = fopen(filename, "rb");
	                                                       
	if (fp == NULL) {
	  return NULL;
	}
	
	// Allocate that many bytes
	bytes_remaining = buf.st_size;
	printf("Devo leggere %d bytes\n------\n",bytes_remaining);    
	p = buffer = malloc(bytes_remaining);
	
	if (buffer == NULL) {
	      return NULL;
	}
	                                                  
	// Read in the entire file
	bytes_read = 0;	
	int tmpByte=fgetc(fp);
	while((tmpByte!=EOF) && (bytes_read<bytes_remaining))
	{
		p[bytes_read++] = tmpByte;
      	tmpByte=fgetc(fp);
	}
	printf("Ho letto:%s\n------\nper un totale di %d bytes\n",p,bytes_read);    
	
	return 0;
}
