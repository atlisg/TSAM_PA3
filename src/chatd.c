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
GTree *fdTree;
GTree *roomTree;
GTree *userTree;

/* Converts IP address and port */
static void ctor(const void *addr, char* ip, int* port){
    const struct sockaddr_in *_addr = addr;
    inet_ntop(AF_INET, &_addr->sin_addr.s_addr, ip, INET_ADDRSTRLEN);
    *port = ntohs(_addr->sin_port);
}

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;
    
    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 != NULL) || (_addr2 != NULL) ||
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

/* Prints out values as GTree is traversed */
void traverse_print(gpointer key, gpointer value, gpointer data){
    int     port;
    char    ip[INET_ADDRSTRLEN];

    struct sockaddr_in *addr = key;
    
    ctor(addr, ip, &port);

    printf("USER: %s:%d\n", ip, port);
    
}

/* Prints out keys and values of userTree */
void traverse_print_userTree(gpointer key, gpointer value, gpointer data) {
    gpointer kei = key;
    struct sockaddr_in *vat = value;
    printf("key: %s", kei);
    printf("value:\nip: %d\nport: %d\n", vat->sin_addr.s_addr, vat->sin_port);
}

/* Prints out all elements in a GList */
void print_list(gpointer elem, gpointer data) {
    struct sockaddr_in *client = &elem;
    printf("%s\n", elem);
}

/* Prints out keys and values of roomTree */
void traverse_print_roomTree(gpointer key, gpointer value, gpointer data) {
    GList *userlist = value;
    
    printf("key: %s\n", key);
    printf("number of users in room: %d\n", g_list_length(userlist));
    printf("value:\n");
    g_list_foreach(userlist, (GFunc) print_list, NULL);
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
void serve(SSL* ssl, struct sockaddr_in *client){
    char    buff[1024];
    int     fd, bytes;

    if(SSL_accept(ssl) == -1){
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Welcome.", 9);

        while((bytes = SSL_read(ssl, buff, sizeof(buff))) > 0){
            buff[bytes] = '\0';
            /* /bye or /quit */
            if (buff[0] == '0' && buff[1] == '2') {
                return;
            }
            /* /user */
            if (buff[0] == '0' && buff[1] == '1') {
                /* Add client to fdTree */
                g_tree_insert(fdTree, ssl, client);
                
                /* Ask for username and password */
                const gchar *str = &buff[3];
                GString *user_pass = g_string_new(str);
                g_tree_insert(userTree, user_pass->str, client);

                /* Split Gstring into two */
                gchar **arr = g_strsplit((gchar*) user_pass->str, ":", 2);
                gpointer username = arr[0];
                
                /* Add user to lobby */
                gpointer userList = g_tree_lookup(roomTree, "Lobby");
                userList = g_list_append(userList, username);

                printf("Number of nodes in fdTree: %d\n", g_tree_nnodes(fdTree));
                g_tree_foreach(fdTree, (GTraverseFunc) traverse_print, NULL);

                printf("Number of nodes in roomTree: %d\n", g_tree_nnodes(roomTree));
                g_tree_foreach(roomTree, (GTraverseFunc) traverse_print_roomTree, NULL);
                
                printf("Number of nodes in userTree: %d\n", g_tree_nnodes(userTree));
                g_tree_foreach(userTree, (GTraverseFunc) traverse_print_userTree, NULL);

                //printf("TODO: check if username is taken\n");
            }
            /* /join */
            if (buff[0] == '0' && buff[1] == '3') {
                printf("TODO: check if room exists\n");
                printf("TODO: add user to room\n");
            }
            /* /who */
            if (buff[0] == '0' && buff[1] == '4') {
                printf("TODO: send list of all users in current room\n");
            }
            /* /list */
            if (buff[0] == '0' && buff[1] == '5') {
                printf("TODO: send a list of all rooms\n");
            }
            /* /say */
            if (buff[0] == '0' && buff[1] == '6') {
                printf("TODO: find the user and send him private message\n");
            }
            buff[bytes] = '\0';
            printf("buff: %s", buff);
            SSL_write(ssl, buff, bytes);
        }
    }
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

    fdTree   = g_tree_new((GCompareFunc) sockaddr_in_cmp);
    roomTree = g_tree_new((GCompareFunc) strcmp);
    userTree = g_tree_new((GCompareFunc) strcmp);

    gpointer lobby = "Lobby";
    GList *userlist = g_list_append(userlist, "GhostRider");
    g_tree_insert(roomTree, lobby, userlist);
    
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
            ctor(&client, cip, &cp);
            log_connection(cip, cp, "connected");

            /* Create new SSL struct */
            ssl = SSL_new(ssl_ctx);

            /* Assign socket to ssl */
            SSL_set_fd(ssl, connfd);
            
            serve(ssl, &client);
            log_connection(cip, cp, "disconnected");
            
            /* Clean up and close connection, free ssl struct */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(connfd);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
    printf("Closing primary socket descriptor\n");
    close(sockfd);
    printf("Freeing SSL context\n");
    SSL_CTX_free(ssl_ctx);
}





