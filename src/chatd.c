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

/* Structs */
struct User {
    char *username;
    char *password;
    char *currRoom;
    SSL *ssl;
};

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
    GString *allUsers = data;
    int     port;
    char    ip[INET_ADDRSTRLEN];
    struct sockaddr_in *kei = key;
    ctor(kei, ip, &port);

    struct User *user = value;
    printf("key:\nip: %s\nport: %d\n", ip, port);
    printf("value: %s\n", user->username);

    if (allUsers != NULL)
        g_string_append_printf(allUsers, ":{Username: %s, IP-address: %s, Port: %d, Room: %s}", user->username, ip, port, user->currRoom);
}

/* Prints out all elements in a GList */
void print_list(gpointer elem, gpointer data) {
    int     port;
    char    ip[INET_ADDRSTRLEN];
    struct sockaddr_in *kei = elem;
    ctor(kei, ip, &port);

    printf("ip: %s\nport: %d\n", ip, port);
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
int serve(SSL* ssl, struct sockaddr_in *client){
    char    buff[1024];
    int     fd, bytes;
    //g_tree_foreach(userTree, (GTraverseFunc) traverse_print_userTree, NULL);
    //g_tree_foreach(roomTree, (GTraverseFunc) traverse_print_roomTree, NULL);
  

    //printf("before SSL_read\n");
    if ((bytes = SSL_read(ssl, buff, sizeof(buff))-1) > 0) {
        buff[bytes] = '\0';
        printf("%s", buff);
        /* /bye or /quit */
        if (buff[0] == '0' && buff[1] == '2') {
            return 0;
        }
        /* /user */
        if (buff[0] == '0' && buff[1] == '1') {
            /* Ask for username and password */
            const gchar *str = &buff[3];
            GString *user_pass = g_string_new(str);

            /* Split Gstring into two */
            gchar **arr = g_strsplit((gchar*) user_pass->str, ":", 2);

            /* Edit the client's username (TODO: if not taken) */
            struct User *userInfo = g_tree_lookup(userTree, client);
            userInfo->username = arr[0];
            userInfo->password = arr[1];

            g_tree_foreach(userTree, (GTraverseFunc) traverse_print_userTree, NULL);
            g_tree_foreach(roomTree, (GTraverseFunc) traverse_print_roomTree, NULL);
            return 1;
        }
        /* /join */
        if (buff[0] == '0' && buff[1] == '3') {
            printf("TODO: check if room exists\n");
            printf("TODO: add user to room\n");
            return 1;
        }
        /* /who */
        if (buff[0] == '0' && buff[1] == '4') {
            GString *allUsers = g_string_new("12");
            g_tree_foreach(userTree, (GTraverseFunc) traverse_print_userTree, allUsers);
            SSL_write(ssl, allUsers->str, allUsers->len);
            return 1;
        }
        /* /list */
        if (buff[0] == '0' && buff[1] == '5') {
            printf("TODO: send a list of all rooms\n");
            return 1;
        }
        /* /say */
        if (buff[0] == '0' && buff[1] == '6') {
            printf("TODO: find the user and send him private message\n");
            return 1;
        }
    }
    //printf("Serve returning 0\n");
    return 1;
}

void initializeUser(SSL* ssl, struct sockaddr_in *client) {
    printf("SSL_write welcome: %d\n", SSL_write(ssl, "Welcome.\r\n", 10));

    struct User *newUser = malloc(sizeof(struct User));
    newUser->username = "Guest";
    newUser->password = "";
    newUser->currRoom = "Lobby";
    newUser->ssl = ssl;

    /* Add client to userTree */
    g_tree_insert(userTree, client, newUser);
    /* Add user to lobby; create lobby if definitely non existent */
    GList *userList = g_tree_lookup(roomTree, newUser->currRoom);
    if (userList == NULL) {
        userList = g_list_append(userList, client);
        g_tree_insert(roomTree, newUser->currRoom, userList);
    } else {
        userList = g_list_append(userList, client);
    }    
}

int main(int argc, char **argv)
{
    gboolean open_socket = FALSE;
    int         sockfd, port;
    char        message[512];
    SSL_CTX*    ssl_ctx;
    SSL*        SSL_fds[FD_SETSIZE];
    fd_set      rfds, afds;

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
    userTree = g_tree_new((GCompareFunc) sockaddr_in_cmp);


    /* Check whether there is data on the socket fd. */
    FD_ZERO(&afds);
    FD_SET(sockfd, &afds);
        
    for (;;) {
        struct timeval      tv;
        struct sockaddr_in  client;
        int                 retval;
        
        /* Wait for five seconds. */ 
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        rfds = afds;
        
        retval = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            int         connfd, cp, i;
            SSL*        ssl;
            char        cip[INET_ADDRSTRLEN]; 

            for (i = 0; i < FD_SETSIZE; ++i) {
                if (FD_ISSET(i, &rfds)) {
                    /* Connecting to original socket */
                    if (i == sockfd) {
                        /* Copy to len, since receive may change it */
                        socklen_t   len = (socklen_t) sizeof(client);

                        /* Data is available, receive it. */
                        assert(FD_ISSET(sockfd, &rfds));
                        
                        /* Accept connection */
                        connfd = accept(sockfd, (struct sockaddr *) &client, &len);

                        /* Create new SSL struct */
                        ssl = SSL_new(ssl_ctx);
 
                        /* Assign socket to ssl */
                        SSL_set_fd(ssl, connfd);

                        /* Attempt SSL connection to client */
                        
                        if(SSL_accept(ssl) == -1){
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            close(connfd);
                            ERR_print_errors_fp(stderr);
                            exit(1);
                        }
                        

                        initializeUser(ssl, &client);
                        printf("User initialized\n");
                        
                        printf("connfd: %d\n", connfd);
                        SSL_fds[connfd] = ssl;
                        FD_SET(connfd, &afds);

                        /* Get client's IP address and port */ 
                        ctor(&client, cip, &cp);
                        log_connection(cip, cp, "connected");
                    } else {
                        ssl = SSL_fds[i];
                        //printf("SSL fd: %d\n", SSL_get_fd(ssl));
                        //printf("SSL_pending: %d\n", SSL_pending(ssl));
                        
                        /* Attempt SSL connection to client */
                        /*
                        if(SSL_accept(ssl) == -1){
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            close(connfd);
                            ERR_print_errors_fp(stderr);
                            exit(1);
                        }
                        */


                        //if(SSL_pending(ssl)){
                            //printf("SSL_pending: %d\n", SSL_pending(ssl));
                            if (!serve(ssl, &client)) {
                                /* The users wants to disconnect */
                                log_connection(cip, cp, "disconnected");

                                /* Clean up and close connection, free ssl struct */
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                close(connfd);
                                FD_CLR(i, &afds);
                            }
                        //}

                    }
                }
            }           
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





