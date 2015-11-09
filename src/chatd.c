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
GTree *roomTree;
GTree *userTree;
GTree *authTree;
int numClients;

/* Structs */
struct User {
    char *username;
    char *currRoom;
    int wrongs;
    SSL *ssl;
};

struct userAuth {
    char *password;
    gboolean isActive;
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

/* Prints out keys and values of userTree */
gboolean traverse_print_userTree(gpointer key, gpointer value, gpointer data) {
    int     port;
    char    ip[INET_ADDRSTRLEN];
    struct sockaddr_in *client = key;
    ctor(client, ip, &port);

    struct User *user = value;
    printf("~KEY~ client: %s:%d\n", ip, port);
    printf("~VAL~ username: %s, room: %s\n", user->username, user->currRoom);

    return FALSE;
}

/* Prints out keys and values of authTree */
gboolean traverse_print_authTree(gpointer key, gpointer value, gpointer data) {
    gchar *username = key;
    struct userAuth *pass_n_act = value;

    printf("~KEY~ username: %s\n", username);
    printf("~VAL~ password: %s, active: %d\n", 
            pass_n_act->password, pass_n_act->isActive);

    return FALSE;
}

/* Colects info from userTree */
void traverse_collect_userTree(gpointer key, gpointer value, gpointer data) {
    GString *allUsers = data;
    int     port;
    char    ip[INET_ADDRSTRLEN];
    struct sockaddr_in *client = key;
    ctor(client, ip, &port);
    struct User *user = value;

    if (allUsers != NULL) {
        g_string_append_printf(allUsers, 
        ":{Username: %s, IP-address: %s, Port: %d, Room: %s}", 
        user->username, ip, port, user->currRoom);
    }
}

/* Prints out all elements in a GList */
void print_list(gpointer elem, gpointer data) {
    int     port;
    char    ip[INET_ADDRSTRLEN];
    struct sockaddr_in *client = elem;
    ctor(client, ip, &port);

    /* Lookup user in userTree to print his name and currRoom */
    struct User *user = g_tree_lookup(userTree, client);
    if (user != NULL) {
        printf("          username: %s, ip: %s, port: %d, room: %s\n", 
                user->username, ip, port, user->currRoom);
    }
}

/* Prints out keys and values of roomTree */
gboolean traverse_print_roomTree(gpointer key, gpointer value, gpointer data) {
    GList   *userlist = value;

    printf("~KEY~ room: %s\n", (char *) key);
    printf("~VAL~ number of users in room: %d\n", g_list_length(userlist));
    printf("      list of users:\n");
    GString *placeholder = g_string_new(NULL);
    g_list_foreach(userlist, (GFunc) print_list, placeholder);

    return FALSE;
}

/* collects info from roomTree */
void traverse_collect_roomTree(gpointer key, gpointer value, gpointer data) {
    GList   *userlist = value;
    GString *allRooms = data;

    if (allRooms != NULL) {
        g_string_append_printf(allRooms, ":{%s}", (char *) key);
    }
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

    printf("\n%s : %s:%d %s\n\n", date, ip, port, msg);
}

// TODO: Send welcome

// TODO: Send private message

// TODO: Broadcast message

/* Switch rooms */
void switchRooms(struct sockaddr_in *client, char *newRoom) {
    /* Fetch the user's info and client struct */
    struct sockaddr_in *userClient;
    struct User *userInfo;
    g_tree_lookup_extended(userTree, client, (gpointer) &userClient, (gpointer) &userInfo);
    
    /* Check if the room he's leaving will become empty */
    GList *currRoomUsers = g_tree_lookup(roomTree, userInfo->currRoom);

    if (g_list_length(currRoomUsers) <= 1) {
        /* If so, remove it */
        g_tree_remove(roomTree, userInfo->currRoom);
    } else {
        /* Else, update the userlist of the room */
        g_tree_insert(roomTree, userInfo->currRoom, g_list_remove(currRoomUsers, userClient));
    }
    userInfo->currRoom = newRoom;

    if (newRoom != NULL) {
        /* Find the current userlist of this room */
        GList *userlist = g_tree_lookup(roomTree, newRoom);
        /* Add him to the list of users in room */
        userlist = g_list_append(userlist, userClient);
        /* Create/update the room  */
        g_tree_insert(roomTree, newRoom, userlist);
    } else {
        /* Remove from userTree and update authTree */
        g_tree_remove(userTree, userClient);
        struct userAuth *auth = g_tree_lookup(authTree, userInfo->username);
        if (auth) {
             auth->isActive = FALSE;
             auth->ssl      = NULL;
        }
    }
}

/* Print trees */
void print() {
//    GString *dummy = g_string_new(NULL);
    printf("\n-----------Displaying userTree---------\n");
    printf("Number of nodes in tree: %d\n", 
            g_tree_nnodes(userTree));
    g_tree_foreach(userTree, 
            (GTraverseFunc) traverse_print_userTree, NULL);

    printf("\n-----------Displaying roomTree---------\n");
    printf("Number of nodes in tree: %d\n", 
            g_tree_nnodes(roomTree));
    g_tree_foreach(roomTree, 
            (GTraverseFunc) traverse_print_roomTree, NULL);
    
    printf("\n-----------Displaying authTree---------\n");
    printf("Number of nodes in tree: %d\n", 
            g_tree_nnodes(authTree));
    g_tree_foreach(authTree, 
            (GTraverseFunc) traverse_print_authTree, NULL);
}

/* Send to Clients in Current room */
void sendMsg(gpointer elem, gpointer data) {
    struct sockaddr_in *client = elem;
    struct User *user = g_tree_lookup(userTree, client);

    /* Send message to all users in room */
    GString *message = g_string_new(data);
    SSL_write(user->ssl, message->str, message->len);
}

/* Broadcast message to all users in room */
void broadcast(struct sockaddr_in *client, const char *message) {
    struct sockaddr_in *currClient;
    struct User *currUser;

    /* Fetch info from userTree */
    g_tree_lookup_extended(userTree, client, (gpointer) &currClient, (gpointer) &currUser);

    /* Fetch list of users in current room */
    GList *roomList = g_tree_lookup(roomTree, currUser->currRoom);

    /* Build and send response to all users in room */
    GString *start = g_string_new("09:");
    g_string_append_printf(start, "%s:%s\r\n", currUser->username, message);
    g_list_foreach(roomList, (GFunc) sendMsg, start->str);
}

/* Sends a private message from the given client to another specified in the message, return TRUE if it succeeds and FALSE if it fails */
gboolean sendPrvMsg(struct sockaddr_in *client, const char *message) {
    /* Split the message into, recipient and the content */
    gchar **strArr   = g_strsplit(message, ":", 2);
    gchar *recipient = strArr[0];
    gchar *content   = strArr[1];
    /* Check whether the recipient exists or not */
    struct userAuth *recipientPtr = g_tree_lookup(authTree, recipient);
    if (recipientPtr) {
        /* If the recipient exists, send him the message and return TRUE */
        struct User *currUser = g_tree_lookup(userTree, client);
        GString *reply = g_string_new("17:");
        g_string_append_printf(reply, "%s:%s:%s\r\n", currUser->username, recipient, content);
        SSL_write(recipientPtr->ssl, reply->str, reply->len);
        SSL_write(currUser->ssl,     reply->str, reply->len);
        return TRUE;
    }
    /* The recipient did not exist, return FALSE */
    return FALSE;
}

/* Serves the given SSL connection */
int serve(SSL* ssl, struct sockaddr_in *client){
    char    buff[1024];
    int     fd, bytes;

        if ((bytes = SSL_read(ssl, buff, sizeof(buff))-2) > 0) {
            buff[bytes] = '\0';
            printf("\nbuff: %s\n", buff);
            
            /* Put message in a GString */
            const gchar *str = &buff[3];
            GString *message = g_string_new(str);

            /* /bye or /quit */
            if (buff[0] == '0' && buff[1] == '2') {
                /* Remove user from current room */
            switchRooms(client, NULL);
            print();
            return 0;
        }

        /* /user */
        if (buff[0] == '0' && buff[1] == '1') {
            /* Fetch user struct */
            struct User *user = g_tree_lookup(userTree, client);
            int port;
            char ip[INET_ADDRSTRLEN];
            ctor(client, ip, &port);

            /* Split Gstring into two */
            gchar **arr = g_strsplit((gchar*) message->str, ":", 2);

            /* Authenticate */
            struct userAuth *val = g_tree_lookup(authTree, arr[0]);
            
            /* GString for auth logging */
            GString *user_auth = g_string_new(arr[0]);

            /* If new user */
            if (val == NULL) {
                val = malloc(sizeof(struct userAuth));
                val->password = arr[1];
                val->ssl      = ssl;
            } else {
                /* Check if user is active */
                if (val->isActive) {
                    g_string_append(user_auth, " authentication error");
                    log_connection(ip, port, user_auth->str);
                    SSL_write(ssl, "15\r\n", 4);
                    return 1;
                }
                /* Check if password is correct */
                if (strcmp(val->password, arr[1]) != 0) {
                    /* Wrong password */
                    if (user->wrongs == 2) {
                        /* Throw user out on the street if 3 wrongs */
                        switchRooms(client, NULL);
                        g_string_append(user_auth, " authentication error");
                        log_connection(ip, port, user_auth->str);
                        SSL_write(ssl, "16\r\n", 4);
                        return 0;
                    }
                    ++user->wrongs;
                    g_string_append(user_auth, " authentication error");
                    log_connection(ip, port, user_auth->str);
                    SSL_write(ssl, "14\r\n", 4);
                    return 1;
                }
            }
            /* Update authTree */
            val->isActive = TRUE;
            val->ssl      = ssl;
            g_tree_insert(authTree, arr[0], val);
            struct userAuth *old = g_tree_lookup(authTree, user->username);
            if (old != NULL) {
                old->isActive = FALSE;
                old->ssl      = NULL;
            }
            /* Update userTree */
            user->username = arr[0];
            user->wrongs   = 0;

            /* Log authentication */
            g_string_append(user_auth, " authenticated");
            log_connection(ip, port, user_auth->str);

            /* Build and send reply to client */
            GString *reply = g_string_new("10:");
            g_string_append_printf(reply, "%s\r\n", arr[0]);
            SSL_write(ssl, reply->str, reply->len);
            print();
            return 1;
        }

        /* /join */
        if (buff[0] == '0' && buff[1] == '3') {
            /* Remove user from current room and add him to new room */
            switchRooms(client, message->str);

            /* Build and send response to client */
            GString *reply = g_string_new("11:");
            g_string_append(reply, message->str);
            g_string_append(reply, "\r\n");
            SSL_write(ssl, reply->str, reply->len);
            print();
            return 1;
        }

        /* /who */
        if (buff[0] == '0' && buff[1] == '4') {
            /* Build and send response to client */
            GString *allUsers = g_string_new("12");
            g_tree_foreach(userTree, (GTraverseFunc) traverse_collect_userTree, allUsers);
            g_string_append(allUsers, "\r\n");
            SSL_write(ssl, allUsers->str, allUsers->len);
            print();
            return 1;
        }

        /* /list */
        if (buff[0] == '0' && buff[1] == '5') {
            /* Build and send response to client */
            GString *allRooms = g_string_new("13");
            g_tree_foreach(roomTree, (GTraverseFunc) traverse_collect_roomTree, allRooms);
            g_string_append(allRooms, "\r\n");
            SSL_write(ssl, allRooms->str, allRooms->len);
            print();
            return 1;
        }

        /* /say */
        if (buff[0] == '0' && buff[1] == '6') {
            const char *str = message->str;
            const char ch   = ':';
            if (strchr(str, ch) == NULL) {
                broadcast(client, str);
            } else {
                if(!sendPrvMsg(client, str)) {
                    GString *reply = g_string_new("18\r\n");
                    SSL_write(ssl, reply->str, reply->len);
                }
            }
            print();
            return 1;
        }
    }
    //printf("Serve returning 0\n");
    return 1;
}

void initializeUser(SSL* ssl, struct sockaddr_in *client) {
    printf("SSL_write welcome: %d\n", SSL_write(ssl, "Welcome.\r\n", 10));

    /* Initializing new User struct */
    GString *username = g_string_new(NULL);
    g_string_printf(username, "%s%d", "Guest", numClients);
    struct User *newUser = malloc(sizeof(struct User));
    newUser->username = username->str;
    newUser->currRoom = "Lobby";
    newUser->wrongs   = 0;
    newUser->ssl      = ssl;

    /* Copying sockaddr_in for the key of the new User */
    struct sockaddr_in *newClient = malloc(sizeof(client));
    memcpy(newClient, client, sizeof(client));

    /* Check if the user already exists? */
    gpointer entry = g_tree_lookup(userTree, newClient);
    if (entry) {
        printf("found this user!\n");
    }

    /* Add client to userTree */
    printf("Inserting new user into userTree!\n");
    g_tree_insert(userTree, newClient, newUser);

    // checking how the userTree looks like now
    printf("------------------\nuserTree (size = %d):\n", g_tree_nnodes(userTree));
    g_tree_foreach(userTree, (GTraverseFunc) traverse_print_userTree, NULL);
    printf("------------------\n");

    /* Add user to lobby; create lobby if definitely non existent */
    GList *userList = g_tree_lookup(roomTree, newUser->currRoom);
    if (userList == NULL) {
        printf("Creating Lobby!\n");
        userList = g_list_append(userList, newClient);
        g_tree_insert(roomTree, newUser->currRoom, userList);
    } else {
        printf("Adding new user to Lobby!\n");
        userList = g_list_append(userList, newClient);
    }    
    printf("------------------\nUsers in Lobby now:\n");
    g_list_foreach(userList, (GFunc) print_list, NULL);
    printf("------------------\n");
    numClients++;
}

int main(int argc, char **argv)
{
    gboolean open_socket = FALSE;
    int         sockfd, port;
    char        message[512];
    numClients = 1;
    SSL_CTX*    ssl_ctx;
    SSL*        SSL_fds[FD_SETSIZE];
    struct sockaddr_in clients[FD_SETSIZE];
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

    roomTree = g_tree_new((GCompareFunc) strcmp);
    userTree = g_tree_new((GCompareFunc) sockaddr_in_cmp);
    authTree = g_tree_new((GCompareFunc) strcmp);

    /* Check whether there is data on the socket fd. */
    FD_ZERO(&afds);
    FD_SET(sockfd, &afds);
        
    for (;;) {
        struct timeval      tv;
        struct sockaddr_in  client;
        int                 retval;
        
        /* Wait for thirty seconds. */ 
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        rfds = afds;
        
        retval = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
            exit(1);
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
                        clients[connfd] = client;
                        FD_SET(connfd, &afds);

                        /* Get client's IP address and port */ 
                        ctor(&client, cip, &cp);
                        log_connection(cip, cp, "connected");
                    } else {
                        ssl = SSL_fds[i];
                        client = clients[i];
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
                                ctor(&client, cip, &cp);
                                log_connection(cip, cp, "disconnected");

                                /* Clean up and close connection, free ssl struct */
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                close(i);
                                FD_CLR(i, &afds);
                            }
                        //}

                    }
                }
            }           
        } else {
            fprintf(stdout, "No message in thirty seconds.\n");
            fflush(stdout);
        }
    }
    printf("Closing primary socket descriptor\n");
    close(sockfd);
    printf("Freeing SSL context\n");
    SSL_CTX_free(ssl_ctx);
}





