#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <dlfcn.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
//#include "polarssl/sha1.h"
//#include "polarssl/base64.h"

//#define PORT "3490"  // the port users will be connecting to
#define PORT "80"  // the port users will be connecting to

#define MAX_HOSTS 10

struct http_data {
  //void (*get)(int socketDescriptor, char * request, unsigned int request_buffer_size, struct hostProperties *host);
  arbitrary get;
  //void (*post)(int socketDescriptor, char * request, unsigned int request_buffer_size, struct hostProperties *host);
  arbitrary post;
  void (*wsrecv)(void);
  void (*wssend)(void (*cb)(void));
};

/**
 * Handle HTTP request and send response
 */
void handle_http_request(int fd/*, struct cache *cache*/, struct http_data data, hostProperties hosts[MAX_HOSTS])
{
    const int request_buffer_size = 65536; // 64K
    char request[request_buffer_size], request_cpy[request_buffer_size];
    char *requestKind;

    // Read request
    int bytes_recvd = recv(fd, request, request_buffer_size - 1, 0);

    
    unsigned char activeHost=0;
    while(activeHost<MAX_HOSTS && (!hosts[activeHost].isActive))
        activeHost++;

    //sprintf(logString,"activeHost:%d with isActive:%d\n",activeHost,hosts[activeHost].isActive);
    //Log("/tmp/webserver.log",logString);

    if (bytes_recvd < 0) {
        perror("recv");
        return;
    }
    else if(hosts[activeHost].isActive)
    {
        //Log("/tmp/webserver.log",request);
        memcpy(request_cpy, request, request_buffer_size);
        
        requestKind = strtok(request," ");
                
        //sprintf(logString, "Kind of request:%s\tResource requested:%s\n",requestKind,requestResource);        
        //printf(logString);       
        if(strcmp(requestKind,"GET")==0) 
        {
            data.get(fd, request_cpy, request_buffer_size, &(hosts[activeHost]));           
        }
        else if(strcmp(requestKind,"POST")==0) 
        {
            data.post(fd, request_cpy, request_buffer_size, &(hosts[activeHost]));
        }
    }
}

static void http_wssend_cb(void)
{
}

//static void http_loop(int idx, char *param)
int main()
{
  /* Variables */
  struct hostProperties hosts[MAX_HOSTS];  
  struct http_data data;
  void *handle;
  char *p, buf[64];
  int newfd, listenfd;                          // listen on sock_fd, new connection on newfd
  struct sockaddr_storage their_addr;           // connector's address information
  unsigned char s[INET6_ADDRSTRLEN];
  unsigned char i, hostFound, hostIndex=0;
  //int idx;
  //struct cache *cache = cache_create(10, 0);
  
  //p = find_param(param, "Plugin");
  //if(p)
  {
//    /* Faccio una sscanf per pulire eventuali terminatori */
//    sscanf(p, "%s", buf);
//    handle = dlopen(ADDROOTDIR(buf), RTLD_NOW);
    printf("Sto per aprire html.so\n");
    handle = dlopen("./html.so", RTLD_LOCAL | RTLD_LAZY);
    printf("Aperto html.so\n");
    if(handle == NULL)
      printf("Handle nullo\n");
    if(handle)
    {
      printf("Sto per prendere la GET\n");
      *(void **)(&(data.get)) = dlsym(handle, "get");
      printf("Sto per prendere la POST\n");
      *(void **)(&(data.post)) = dlsym(handle, "post");
      data.wsrecv = dlsym(handle, "http_wsrecv");
      data.wssend = dlsym(handle, "http_wssend");
      printf("Tutto a posto a ferragosto anche se siamo a Dicembre quasi\n");

      if(data.get == NULL)
        printf("Problema get\n");
      if(data.post == NULL)
        printf("Problema post\n");

      /* Registra la callback per i dati websocket */
      if(data.wssend) data.wssend(http_wssend_cb);
    }
    else
    {
      //Log(idx, "Errore caricamento plugin");
    }
    
    //free(p);
  }
  
  // Get a listening socket
  listenfd = get_listener_socket(PORT);

  if (listenfd < 0) {
      fprintf(stderr, "webserver: fatal error getting listening socket\n");
      exit(1);
  }

  fprintf(stderr, "webserver: waiting for connections on port %s...\n", PORT);

  while(1)
  {
    /* Loop principale */
    /* Si chiamano data.get() o data.post() quando si ricevono queste
       richieste via HTTP.
       Si chiama data.wsrecv() quando vengono ricevuti dati dal
       websocket e li si passa al plugin.
       I dati che il plugin produce per essere inviati sul websocket
       arrivano alla callback registrata. */

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
              //sprintf(tmpString, "Host found with index %d\n", i);
              //Log("/tmp/webserver.log",tmpString);
          }
          else
          {
              hosts[i].isActive = 0;            
              //sprintf(tmpString, "Host not found: %s\n",s);
              //Log("/tmp/webserver.log",tmpString);
          }
      }
      if(!hostFound)
      {
          strcpy((char *)hosts[hostIndex].hostIP,(char *)s);
          //sprintf(tmpString, "Adding host: %s on index: %d\n",hosts[hostIndex].hostIP, hostIndex);
          //Log("/tmp/webserver.log",tmpString);    
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

      handle_http_request(newfd/*, cache*/, data, hosts);

      close(newfd);
  }
}

void _init()
{
  printf("Plugin HTTP: " __DATE__ " " __TIME__ "\n");
  register_plugin("HTTP", 1, http_loop);
}
