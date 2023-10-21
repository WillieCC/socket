#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_SERVER_PORT 8600
#define SOCKET_TIMEOUT 15
#define ENABLE_SOCKET_NO_DELAY 1
#define ENABLE_SOCKET_REUSEADDR 1
#define MAX_SOCKET_RX_BUFFER (1024*1024)
#define MAX_SOCKET_TX_BUFFER (1024*1024)
#define DOMAIN_SOCKET_SERVER "/tmp/test_socket"

#ifndef UNUSED
#define UNUSED(X) if(0){X=X;};
#endif

union AddressUnion {
    struct sockaddr_in ipv4_addr;
    struct sockaddr_un unix_addr;
};
  
typedef struct
{
    uint8_t bind_ethernet[100];//Bind Ethernet device
    uint16_t port;    //port number;
    uint8_t max_sessions;
    uint8_t isdelay;  
    uint8_t isreuse;  
}socket_config_t;
   
typedef struct
{
    int32_t socket_server;
    int32_t socket_client;
    union AddressUnion addr;
    socket_config_t config;
    int8_t* rx_buf;
    int8_t* tx_buf;
}socket_handler_t;

static inline void dump_ethernet(int32_t sock_fd)
{
    struct sockaddr_in addr;
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    socklen_t addr_len;
    int8_t str[INET_ADDRSTRLEN];
    const char *ptr;

    addr_len = sizeof (addr);
    getsockname(sock_fd, (struct sockaddr*)&addr, &addr_len);
    getifaddrs(&ifaddr);

    // look for all interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr)
        {
            if (AF_INET == ifa->ifa_addr->sa_family)
            {
                struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;
                ptr = inet_ntop(AF_INET,&inaddr->sin_addr, (char*)str, sizeof(str));
                printf("Ethernet:%s ,ip:%s\n",ifa->ifa_name,ptr);	
            }
        }
    }

    freeifaddrs(ifaddr);
}

static inline int32_t socket_connect(socket_handler_t* handler)
{
    if (connect(handler->socket_client, (struct sockaddr*)&handler->addr.unix_addr, sizeof(handler->addr.unix_addr)) == -1)
    {
        perror("connect failed");
        return (-1);
    }

    return 0;
}

static inline int32_t socket_accept(socket_handler_t* handler)
{
    struct sockaddr_in clientInfo;     
    unsigned int addrlen =sizeof(clientInfo);
    if(handler==NULL)
    {
        return -EINVAL;
    }

    while (1) {
        handler->socket_client = accept(handler->socket_server,(struct sockaddr*) &clientInfo, &addrlen);
        if (handler->socket_client != -1) {
            break;
        }

        if (errno != EINTR && \
            errno != EAGAIN && \
            errno != EINPROGRESS ) 
        {
            break;
        }
    }

    return handler->socket_client;
}

static inline int32_t socket_select(int32_t fd)
{
    struct timeval tv;
    fd_set rfds;
    int32_t ret;

    if(fd < 0) 
    {
        return -EINVAL;
    }

    tv.tv_sec = SOCKET_TIMEOUT;
    tv.tv_usec = 0;
    FD_ZERO(&rfds); 
    FD_SET(fd,&rfds);   
    ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if(ret < 0)
    {
        return -1;
    }

    return FD_ISSET(fd,&rfds) ? 1 : 0;
}


static inline int32_t socket_recvfrom(int32_t fd,struct sockaddr *addr,const void* rx_buf, size_t sz_len)
{
    int32_t ret=0;
    socklen_t len;
    len=sizeof(struct sockaddr);
    while (1) {
        ret = recvfrom(fd,(char*)rx_buf,sz_len,0,(struct sockaddr*)addr, &len);
        if (ret != -1) {
            break;
        }

        if (errno != EINTR && errno!=EAGAIN) {
            break;
        }
    }

    return ret;
}

static inline int32_t socket_sendto(int32_t fd, struct sockaddr* addr, const char* tx_buf, size_t sz_len)
{
    int32_t ret=0;
    while (1) {
        ret = sendto(fd, tx_buf, sz_len, 0, addr, sizeof(struct sockaddr));
        if (ret != -1) {
            break;
	}
		
        if (errno != EINTR && errno!=EAGAIN) {
            break;
	    }
    }

    return ret;
}

static inline int32_t socket_recv(int32_t fd, char* rx_buf, size_t sz_len)
{
    int32_t ret=0;

    ret=socket_select(fd);
    if(ret<=0)
    {
        return ret;
    }

    while(1)
    {
        ret = recv(fd,(char*)rx_buf,sz_len,0);
        if (ret != -1) {
            break;
	    }
		
	    if (errno != EINTR && errno!=EAGAIN) {
            break;
        }
    }

    printf("%s\n",rx_buf);
    return ret;
}

static inline int32_t socket_send(int32_t fd, const char* tx_buf,size_t sz_len)
{
    int32_t ret=0;

    while (1) {
        ret = send(fd, tx_buf, sz_len, 0); \
        if (ret != -1)	
        {
            break;
        }

	    if (errno != EINTR && errno!=EAGAIN)
        {
            break;
        }
    }

    return ret;
}

static inline int32_t socket_disconnect(socket_handler_t* handler)
{
    if(handler->socket_client >0) 
    {
        shutdown(handler->socket_client,SHUT_RDWR);
        close(handler->socket_client);
        handler->socket_client=-1;
    }

    return 0;
}

static inline int32_t load_socket_config(socket_handler_t* handler)
{
    memset(&handler->config,0,sizeof(socket_config_t));    
    handler->rx_buf=malloc(1024*1024);
    handler->tx_buf=malloc(1024*1024);
    handler->config.max_sessions=10;    
    handler->config.isdelay=ENABLE_SOCKET_NO_DELAY;
    handler->config.isreuse=ENABLE_SOCKET_REUSEADDR;    
    handler->config.port=SOCKET_SERVER_PORT;
    return 0;
}

static inline int32_t create_local_server(socket_handler_t* handler, int32_t socket_type)
{
    handler->addr.unix_addr.sun_family = AF_UNIX;
    handler->socket_server = socket(AF_UNIX, socket_type, 0);
    if (handler->socket_server < 0) 
    {
        perror("create socket failed");
        exit(-1);
    }
	
    if (bind(handler->socket_server, (struct sockaddr*)&handler->addr.unix_addr, sizeof(handler->addr.unix_addr)) == -1) 
    {
        perror("bind failed");
        close(handler->socket_server);
        return -1;
    }

    if (listen(handler->socket_server, handler->config.max_sessions) == -1) 
    {
        perror("listen failed");
        close(handler->socket_server);
        return -1;
    }

    return 0;
}

static inline int32_t create_local_client(socket_handler_t* handler, int32_t socket_type)
{
    handler->socket_client = socket(AF_UNIX, socket_type, 0);
    if (handler->socket_client == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    handler->addr.unix_addr.sun_family = AF_UNIX;
    strcpy(handler->addr.unix_addr.sun_path, DOMAIN_SOCKET_SERVER);

    return 0;
}


static inline int32_t create_socket_server(socket_handler_t* handler, int32_t socket_type)
{
    struct addrinfo hints;      // Used for the getaddrinfo call
    struct addrinfo *servinfo;  // Server address info
    char portStr[6];            // String to store port number 
    int retval=0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = socket_type; //TCP:SOCK_STREAM, UDP:SOCK_DGRAM
    hints.ai_flags = AI_PASSIVE;
    snprintf(portStr, sizeof(portStr), "%u",handler->config.port);
    
    retval = getaddrinfo(NULL, portStr, &hints, &servinfo);
    if (retval != 0) 
    {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(retval));
        exit(-1);
    }

    handler->socket_server = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (-1 == handler->socket_client) 
    {
        perror("socket failed");
        return -1;   
    }
  
    if(socket_type==SOCK_STREAM)
    { 
        if (setsockopt(handler->socket_server, IPPROTO_TCP, TCP_NODELAY, &handler->config.isdelay,sizeof(handler->config.isdelay)))
        {
            perror("TCP_NODELAY failed");
        }
    }

    if (setsockopt(handler->socket_server, SOL_SOCKET, SO_REUSEADDR, &handler->config.isreuse,sizeof(handler->config.isreuse)))	
    {
        perror("SO_REUSEADDR failed");
    }

    dump_ethernet(handler->socket_server);

    if (bind(handler->socket_server,servinfo->ai_addr, servinfo->ai_addrlen) < 0)
    {
        close(handler->socket_client);
        handler->socket_client = -1;
        freeaddrinfo(servinfo);
        perror("socket server bind failed");
        return -1;
    }

    freeaddrinfo(servinfo);

    // Listen TCP connection
    if(socket_type==SOCK_STREAM)
    {
        if (listen(handler->socket_server, handler->config.max_sessions) < 0)
        {
            close(handler->socket_server);
            handler->socket_server = -1;
            perror("socket listen failed\n");
            return -1;
        }
    }

    return 0;
}

void Test_domain_socket_server()
{
    const char* message = "Hi,this is server";
    socket_handler_t DomainSocket;
    strcpy(DomainSocket.addr.unix_addr.sun_path, DOMAIN_SOCKET_SERVER);
    load_socket_config(&DomainSocket);
    create_local_server(&DomainSocket,SOCK_STREAM);
    
    while(1)
    {
        if(socket_accept(&DomainSocket)>0)
        {
            memcpy(DomainSocket.tx_buf,message,strlen(message));
            socket_recv(DomainSocket.socket_client,(void*)DomainSocket.rx_buf,MAX_SOCKET_RX_BUFFER);
    	    socket_send(DomainSocket.socket_client,message,strlen(message));
            socket_disconnect(&DomainSocket);
        }
    }

    unlink(DOMAIN_SOCKET_SERVER);
}

void Test_domain_socket_client()
{
    const char* message = "Hi, this is client";
    socket_handler_t DomainSocket;
    load_socket_config(&DomainSocket);
    create_local_client(&DomainSocket,SOCK_STREAM);

    if (socket_connect(&DomainSocket) == -1) {
        socket_disconnect(&DomainSocket);
        exit(EXIT_FAILURE);
    }

    socket_send(DomainSocket.socket_client,message,strlen(message));
    socket_recv(DomainSocket.socket_client,(void*)DomainSocket.rx_buf,MAX_SOCKET_RX_BUFFER);
    socket_disconnect(&DomainSocket);
}

void Test_UDP_socket_server()
{
    socket_handler_t udp_socket;
    load_socket_config(&udp_socket);
    create_socket_server(&udp_socket,SOCK_DGRAM);
    while(1)
    {
        socket_recvfrom(udp_socket.socket_server,(struct sockaddr*)&udp_socket.addr.ipv4_addr,(void*)udp_socket.rx_buf,MAX_SOCKET_RX_BUFFER);
    }
}
 
void Test_TCP_socket_server()
{
    const char* message = "Hi, this is client";
    socket_handler_t tcp_socket;
    load_socket_config(&tcp_socket);
    create_socket_server(&tcp_socket,SOCK_STREAM);
    
    while(1)
    {
        if(socket_accept(&tcp_socket)>0)
        {
            socket_recv(tcp_socket.socket_client,(void*)tcp_socket.rx_buf,MAX_SOCKET_RX_BUFFER);
    	    socket_send(tcp_socket.socket_client,message,strlen(message));
            socket_disconnect(&tcp_socket);
        }
    }
}

void Test_http_socket_server()
{
    socket_handler_t tcp_socket;
    load_socket_config(&tcp_socket);
    create_socket_server(&tcp_socket,SOCK_STREAM);
    const char *response = "HTTP/1.1 200 OK\r\n"
                      "Content-Length: 13\r\n"
                      "Content-Type: text/plain\r\n"
                      "\r\n"
                      "Hello, World!\r\n";
    while(1)
    {
        if(socket_accept(&tcp_socket)>0)
        {
            socket_recv(tcp_socket.socket_client,(void*)tcp_socket.rx_buf,MAX_SOCKET_RX_BUFFER);
    	    socket_send(tcp_socket.socket_client,response,strlen(response));
            socket_disconnect(&tcp_socket);
        }
    }
}

#endif

