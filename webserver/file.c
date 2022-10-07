#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "file.h"

/**
 * Loads a file into memory and returns a pointer to the data.
 * 
 * Buffer is not NUL-terminated.
 */
struct file_data *file_load(char *filename)
{
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
    //printf("Devo leggere %d bytes\n------\n",bytes_remaining);    
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
    p[bytes_read] = '\0';
    //printf("Ho letto:\n%s\n------\n",p);

    // Allocate the file data struct
    struct file_data *filedata = malloc(sizeof *filedata);
    if (filedata == NULL) {
        free(buffer);
        return NULL;
    }

    filedata->data = buffer;
    //filedata->size = total_bytes;
    filedata->size = bytes_read;

    return filedata;
}

/**
 * Frees memory allocated by file_load().
 */
void file_free(struct file_data *filedata)
{
    free(filedata->data);
    free(filedata);
}