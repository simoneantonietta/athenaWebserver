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
#include "mime.h"
#include "cache.h"
#include "server.h"
#include <time.h>

//#define PORT "3490"  // the port users will be connecting to
#define PORT "80"  // the port users will be connecting to

#define MAX_HOSTS 10

/* Variables */
struct hostProperties hosts[MAX_HOSTS];

/**
 * Handle HTTP request and send response
 */
void handle_http_request(int fd/*, struct cache *cache*/)
{
    const int request_buffer_size = 65536; // 64K
    char request[request_buffer_size], request_cpy[request_buffer_size];
    char *requestKind, logString[100];

    // Read request
    int bytes_recvd = recv(fd, request, request_buffer_size - 1, 0);

    
    unsigned char activeHost=0;
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
        
        //requestResource = strtok(NULL," ");
        
        //sprintf(logString, "Kind of request:%s\tResource requested:%s\n",requestKind,requestResource);        
        //printf(logString);       
        if(strcmp(requestKind,"GET")==0) 
        {
            get(fd, request_cpy, request_buffer_size, &(hosts[activeHost]));           
        }
        else if(strcmp(requestKind,"POST")==0) 
        {
            post(fd, request_cpy, request_buffer_size, &(hosts[activeHost]));
        }
    }
    else
    {
        resp_404(fd);
    }
}

/**
 * Main
 */
int main(void)
{
    int newfd;  // listen on sock_fd, new connection on newfd
    struct sockaddr_storage their_addr; // connector's address information
    unsigned char s[INET6_ADDRSTRLEN];
    char tmpString[200];
    unsigned char i, hostFound, hostIndex=0;

    //struct cache *cache = cache_create(10, 0);

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
            (char *)s, sizeof s);
        //printf("server: got connection from %s\n", s);
        //sprintf(tmpString, "server: got connection from %s\n", s);
        //Log("/tmp/webserver.log",tmpString);

        for(i=0,hostFound=0;i<MAX_HOSTS && hostFound==0;i++)
        {
            if(strcmp((char *)s,(char *)hosts[i].hostIP)==0)
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
            strcpy((char *)hosts[hostIndex].hostIP,(char *)s);
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

        handle_http_request(newfd/*, cache*/);

        close(newfd);
    }

    // Unreachable code

    return 0;
}

