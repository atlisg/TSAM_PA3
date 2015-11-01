/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <termios.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* To convert IP address */
#include <arpa/inet.h>

/* Definables */
#define CHECK_NULL(x, s)    if((x)==NULL)   {perror(s); exit(1);}
#define CHECK_ERR(x, s)     if((x)==-1)     {perror(s); exit(1);}

#define SERVER_CERT "src/fd.crt"
#define SERVER_KEY  "src/fd.key"

/* Global data structures used */ 

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
            (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

/* Initalizes context */
SSL_CTX* init_CTX(){
    printf("Initalizing SSL context\n");
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLSv1_server_method());
    CHECK_NULL(ctx, "SSL_CTX_new");
    
    return ctx;
}

/* Loads certificates into context */
void load_certificates(SSL_CTX* ctx){
    printf("Loading certificates\n");
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // CA file?

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

/* Create a server socket */
int open_listener(int server_port){
    printf("Creating the socket and listening\n");

    struct  sockaddr_in server;
    int     sock_fd;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK_ERR(sock_fd, "socket");

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(server_port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    
    /* Bind port */
    CHECK_ERR(bind(sock_fd, (struct sockaddr*)&server, sizeof(server)), "bind");

    /* Listen to port, allow 1 connection */
    CHECK_ERR(listen(sock_fd, 1), "listen");

    return sock_fd;
}

/* Logs a line when a client connects/disconnects/authorizes */
void log_connection(char ip[INET_ADDRSTRLEN], int port, char* msg){
    time_t  t;
    char    date[20];

    t = time(NULL);
    strftime(date, sizeof(date), "%FT%T\n", localtime(&t));

    printf("%s : %s:%d %s\n", date, ip, port, msg);
}

// TODO: Send welcome

// TODO: Send private message

// TODO: Broadcast message

/* Serves the given SSL connection */
void serve(SSL* ssl){
    char    buff[1024], reply[1024];
    int     fd, bytes;

    if(SSL_accept(ssl) == -1){
        ERR_print_errors_fp(stderr);
    } else {
        sprintf(reply, "Welcome to the SSL server");
        SSL_write(ssl, reply, strlen(reply));
        while((bytes = SSL_read(ssl, buff, sizeof(buff))) > 0){
            buff[bytes] = '\0';
            printf("%s\n", buff);

        }

    }
    fd = SSL_get_fd(ssl);
    //SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
}

int main(int argc, char **argv)
{
    int         sockfd, port;
    char        message[512];
    SSL_CTX*    ssl_ctx;

    if(argc < 2){
        perror("1 argument required (port#)");
        exit(1);
    }
    port = (int)atoi(argv[1]);
    
    /* Initalize OpenSSL */
    SSL_library_init();

    ssl_ctx = init_CTX();
    load_certificates(ssl_ctx);
    sockfd = open_listener(port);

    for (;;) {
        fd_set              rfds;
        struct timeval      tv;
        struct sockaddr_in  client;
        int                 retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            int         connfd, cp;
            SSL*        ssl;
            char        cip[INET_ADDRSTRLEN]; 
            socklen_t   len = (socklen_t) sizeof(client);

            /* Data is available, receive it. */
            assert(FD_ISSET(sockfd, &rfds));

            /* Accept connection */
            connfd = accept(sockfd, (struct sockaddr *) &client, &len);
           
            /* Get client's IP address and port */ 
            inet_ntop(AF_INET, &client.sin_addr.s_addr, cip, INET_ADDRSTRLEN);
            cp = ntohs(client.sin_port);
            log_connection(cip, cp, "connected");

            /* Create new SSL struct */
            ssl = SSL_new(ssl_ctx);

            /* Assign socket to ssl */
            SSL_set_fd(ssl, connfd);

            serve(ssl);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
    close(sockfd);
    SSL_CTX_free(ssl_ctx);
}
