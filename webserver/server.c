/**
 * webserver.c -- A webserver written in C
 * 
 * Test with curl (if you don't have it, install it):
 * 
 *    curl -D - http://localhost:3490/
 *    curl -D - http://localhost:3490/d20
 *    curl -D - http://localhost:3490/date
 * 
 * You can also test the above URLs in your browser! They should work!
 * 
 * Posting Data:
 * 
 *    curl -D - -X POST -H 'Content-Type: text/plain' -d 'Hello, sample data!' http://localhost:3490/save
 * 
 * (Posting data is harder to test from a browser.)
 */

#include "net.h"
#include "file.h"
#include "mime.h"
#include "cache.h"
#include "server.h"

//#define PORT "3490"  // the port users will be connecting to
#define PORT "80"  // the port users will be connecting to

#define SERVER_FILES "/home/utente/serverfiles/"
#define SERVER_ROOT "/home/utente/serverroot"

#define MAX_HOSTS 10

typedef struct hostProperties{
    unsigned char hostIP[INET6_ADDRSTRLEN];      // IP address of a host
    unsigned char authorized;                    // authorization state of a host
    unsigned char isActive;                      // the host made the last request
}hostProperties;

/* Variables */
struct hostProperties hosts[MAX_HOSTS];

/**
 * Send an HTTP response
 *
 * header:       "HTTP/1.1 404 NOT FOUND" or "HTTP/1.1 200 OK", etc.
 * content_type: "text/plain", etc.
 * body:         the data to send.
 * 
 * Return the value from the send() function.
 */
int send_response(int fd, char *header, char *content_type, void *body, int content_length)
{
    const int max_response_size = 262144;
    char response[max_response_size];

    // Build HTTP response and store it in response

    //printf("Content lenght:%d\n",content_length);    
    unsigned int index, i;
    for(i=0, index=0;i<strlen(header);i++,index++)
        response[index] = header[i];
    response[index++] = '\n';
    for(i=0;i<strlen(content_type);i++,index++)
        response[index] = content_type[i];
    response[index++] = '\n';
    response[index++] = '\n';
    for(i=0;i<content_length;i++,index++)
        response[index] = ((char *)body)[i];
    response[index++] = '\n';
    response[index++] = '\0';

    //printf("Response:\n%s\nTotal lenght:%d\n",response,index);
	
    int response_length = index;

    // Send it all!
    int rv = send(fd, response, response_length, 0);

    if (rv < 0) {
        perror("send");
    }

    return rv;
}


/**
 * Send a /d20 endpoint response
 */
void get_d20(int fd)
{
    // Generate a random number between 1 and 20 inclusive
    
    ///////////////////
    // IMPLEMENT ME! //
    ///////////////////

    // Use send_response() to send it back as text/plain data

    ///////////////////
    // IMPLEMENT ME! //
    ///////////////////
}

/**
 * Send a 404 response
 */
void resp_404(int fd)
{
    char filepath[4096];
    struct file_data *filedata; 
    char *mime_type;

    // Fetch the 404.html file
    snprintf(filepath, sizeof filepath, "%s/404.html", SERVER_FILES);
    filedata = file_load(filepath);

    if (filedata == NULL) {
        // TODO: make this non-fatal
        fprintf(stderr, "cannot find system 404 file\n");
        exit(3);
    }

    mime_type = mime_type_get(filepath);

    send_response(fd, "HTTP/1.1 404 NOT FOUND", mime_type, filedata->data, filedata->size);

    file_free(filedata);
}

/**
 * Read and return a file from disk or cache
 */
void get_file(int fd, struct cache *cache, char *request_path)
{
    ///////////////////
    // IMPLEMENT ME! //
    ///////////////////
}

/**
 * Search for the end of the HTTP header
 * 
 * "Newlines" in HTTP can be \r\n (carriage return followed by newline) or \n
 * (newline) or \r (carriage return).
 */
char *find_start_of_body(char *header)
{
    ///////////////////
    // IMPLEMENT ME! // (Stretch)
    ///////////////////
}

/**
 * Handle HTTP request and send response
 */
void handle_http_request(int fd, struct cache *cache)
{
    const int request_buffer_size = 65536; // 64K
    char request[request_buffer_size], request_cpy[request_buffer_size];
    char *requestKind, *requestResource, logString[100];

    char filepath[4096];
    struct file_data *filedata; 
    char *mime_type, credentials[256], credentials_b64[256], reference_credential[256], *tmpString;
    char idx;

    char pwdName[] = "/home/utente/serverroot/pwd";
    FILE * fDesc;

    formValues formVal;

    // Read request
    int bytes_recvd = recv(fd, request, request_buffer_size - 1, 0);

    
    char activeHost=0;
    while(activeHost<MAX_HOSTS && (!hosts[activeHost].isActive))
        activeHost++;

    sprintf(logString,"activeHost:%d with isActive:%d\n",activeHost,hosts[activeHost].isActive);
    Log("/tmp/webserver.log",logString);

    if (bytes_recvd < 0) {
        perror("recv");
        return;
    }
    else if(hosts[activeHost].isActive)
    {
        //Log("/tmp/webserver.log",request);
        memcpy(request_cpy, request, request_buffer_size);
        
        requestKind = strtok(request," ");
        requestResource = strtok(NULL," ");
        sprintf(logString, "Kind of request:%s\tResource requested:%s\n",requestKind,requestResource);        
        printf(logString);       
        if(strcmp(requestKind,"GET")==0) 
        {
            printf("GET detected\n");
            Log("/tmp/webserver.log","GET detected\n");

            // Fetch the file requested 
            snprintf(filepath, sizeof filepath, "%s%s", SERVER_ROOT, requestResource);
            filedata = file_load(filepath);

            if (filedata == NULL) {
                fprintf(stderr, "cannot find system %s file\n",requestResource);
                snprintf(filepath, sizeof filepath, "%s/index.html", SERVER_ROOT);
                filedata = file_load(filepath);
            }            

            mime_type = mime_type_get(filepath);

            //printf("Mime type:%s\n\n",mime_type);

            if(hosts[activeHost].authorized)
            {
                strcpy(logString,"Authorized\n");
                Log("/tmp/webserver.log",logString);
                
                send_response(fd, "HTTP/1.1 200 OK", mime_type, filedata->data, filedata->size);
            }
            else
            {
                strcpy(logString,"Unathorized\n");
                Log("/tmp/webserver.log",logString);
                
                tmpString = strstr(request_cpy,"Authorization: ");

                if(tmpString)
                {
                    for(idx=0;(tmpString[idx+strlen("Authorization: Basic ")]!='\r') && (idx<sizeof(credentials_b64));idx++)
                    {
                        credentials_b64[idx]=tmpString[idx+strlen("Authorization: Basic ")];                        
                    }                
                    credentials_b64[idx] = '\0';

                    b64_decode(credentials_b64, credentials); 

                    fDesc = fopen(pwdName,"r");
                    fgets(reference_credential,sizeof(reference_credential),fDesc);
                    fclose(fDesc);

                    /*sprintf(logString,"reference_credential:%s\n",reference_credential);
                    Log("/tmp/webserver.log",logString);*/
                        
                    if(strncmp(credentials,reference_credential,strlen(reference_credential))==0)
                    {
                        hosts[activeHost].authorized = 1;
                        send_response(fd, "HTTP/1.1 200 OK", mime_type, filedata->data, filedata->size);
                    }
                    else
                        send_response(fd, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic", mime_type, NULL, NULL);
                }
                else
                    send_response(fd, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic", mime_type, NULL, NULL);
            }
            
            file_free(filedata);
        }
        else if(strcmp(requestKind,"POST")==0) 
        {
            printf("POST detected\n");
            Log("/tmp/webserver.log","POST detected\n");               
            int result= parseForm(request_cpy, &formVal);
            Log("/tmp/webserver.log","POST parsified\n");               
            changeIP(&formVal);
            Log("/tmp/webserver.log","NETWORK changed\n");               
            if(result)         
            {
                sprintf(logString, "Form Values detected:%d\n",result);        
                Log("/tmp/webserver.log", logString);
            }
            // Fetch the index.html file
            snprintf(filepath, sizeof filepath, "%s%s", SERVER_ROOT, requestResource);
            filedata = file_load(filepath);

            if (filedata == NULL) {
                // TODO: make this non-fatal
                fprintf(stderr, "cannot find system %s file\n",requestResource);
                //exit(3);
                snprintf(filepath, sizeof filepath, "%s/index.html", SERVER_ROOT);
                filedata = file_load(filepath);
            }

            mime_type = mime_type_get(filepath);

            send_response(fd, "HTTP/1.1 200 OK", mime_type, filedata->data, filedata->size);
            file_free(filedata);
        }
    }

    ///////////////////
    // IMPLEMENT ME! //
    ///////////////////

    // Read the first two components of the first line of the request 
 
    // If GET, handle the get endpoints

    //    Check if it's /d20 and handle that special case
    //    Otherwise serve the requested file by calling get_file()


    // (Stretch) If POST, handle the post request
}

/**
 * Main
 */
int main(void)
{
    int newfd;  // listen on sock_fd, new connection on newfd
    struct sockaddr_storage their_addr; // connector's address information
    char s[INET6_ADDRSTRLEN];
    char tmpString[200];
    char i, hostFound, hostIndex=0;

    struct cache *cache = cache_create(10, 0);

    // Get a listening socket
    int listenfd = get_listener_socket(PORT);

    if (listenfd < 0) {
        fprintf(stderr, "webserver: fatal error getting listening socket\n");
        exit(1);
    }

    printf("webserver: waiting for connections on port %s...\n", PORT);

    // This is the main loop that accepts incoming connections and
    // responds to the request. The main parent process
    // then goes back to waiting for new connections.
    
    while(1) {
        socklen_t sin_size = sizeof their_addr;

        // Parent process will block on the accept() call until someone
        // makes a new connection:
        newfd = accept(listenfd, (struct sockaddr *)&their_addr, &sin_size);
        if (newfd == -1) {
            perror("accept");
            continue;
        }

        // Print out a message that we got the connection
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);
        sprintf(tmpString, "server: got connection from %s\n", s);
        Log("/tmp/webserver.log",tmpString);

        for(i=0,hostFound=0;i<MAX_HOSTS && hostFound==0;i++)
        {
            if(strcmp(s,hosts[i].hostIP)==0)
            {   
                hostFound = 1;
                hosts[i].isActive = 1;
                sprintf(tmpString, "Host found with index %d\n", i);
                Log("/tmp/webserver.log",tmpString);
            }
            else
            {
                hosts[i].isActive = 0;            
                sprintf(tmpString, "Host not found: %s\n",s);
                Log("/tmp/webserver.log",tmpString);
            }
        }
        if(!hostFound)
        {
            strcpy(hosts[hostIndex].hostIP,s);
            sprintf(tmpString, "Adding host: %s on index: %d\n",hosts[hostIndex].hostIP, hostIndex);
            Log("/tmp/webserver.log",tmpString);    
            for(i=0;i<MAX_HOSTS;i++)
            {
                if(i!=hostIndex)
                    hosts[i].isActive = 0;        
                else
                    hosts[i].isActive = 1;
            }
            hosts[hostIndex].authorized = 0;
            hostIndex = (hostIndex+1)%MAX_HOSTS;           // no more than MAX_HOSTS hosts managed
            hostFound = 1;            
        }        
        
        // newfd is a new socket descriptor for the new connection.
        // listenfd is still listening for new connections.

        handle_http_request(newfd, cache);

        close(newfd);
    }

    // Unreachable code

    return 0;
}

