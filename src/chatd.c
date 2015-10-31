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

#define SERVER_CERT "src/fd.crt"
#define KEY_FILE  "src/fd.key"
//#define CA_FILE   "src/fd.csr"

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



int main(int argc, char **argv)
{
    int sockfd, port;
    struct sockaddr_in server, client;
    char message[512];
    SSL *ssl;

    if(argc < 2){
        perror("1 argument required (port#)");
        exit(1);
    }
    port = (int)atoi(argv[1]);

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    /* Initialize SSL Library */
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());

    /* Use our certificate file */
    if (SSL_CTX_use_certificate_file(ssl_ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* Use our private key file */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* Load CA */
    //        if (!SSL_CTX_load_verify_locations(ssl_ctx, CA_FILE, NULL)) {
    //            ERR_print_errors_fp(stderr);
    //            exit(1);
    //        }
    /* Require client verification */
    //        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    /* Set depth of verification */
    //        SSL_CTX_set_verify_depth(ssl_ctx, 1);

    /* Before we can accept messages, we have to listen to the port. We allow one
     * 1 connection to queue for simplicity.
     */
    listen(sockfd, 1);

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

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
            /* Data is available, receive it. */
            assert(FD_ISSET(sockfd, &rfds));

            /* Copy to len, since recvfrom may change it. */
            socklen_t len = (socklen_t) sizeof(client);

            /* For TCP connectios, we first have to accept. */
            int connfd;
            connfd = accept(sockfd, (struct sockaddr *) &client,
                    &len);

            printf ("TCP Connection from %lx, port %x\n",
                    client.sin_addr.s_addr, client.sin_port);

            /* TCP connection ready, create new SSL struct */
            ssl = SSL_new(ssl_ctx);

            /* Assign socket to ssl */
            SSL_set_fd(ssl, connfd);

            /* Perform handshake on SSL server */
            SSL_accept(ssl);

            printf("Welcome.\n");
            printf("SSL connection using %s\n", SSL_get_cipher (ssl));

            /* Receive one byte less than declared,
               because it will be zero-termianted
               below. */
            ssize_t n = SSL_read(ssl, message, sizeof(message) - 1);

            /* Send a message back to the client. */
            char *reply = "This message is from the SSL server";
            SSL_write(ssl, reply, strlen(reply));

            /* We should close the connection. */
            SSL_shutdown(ssl);
            close(connfd);

            /* Free */
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);

            /* Zero terminate the message, otherwise
               printf may access memory outside of the
               string. */
            message[n] = '\0';
            /* Print the message to stdout and flush. */
            fprintf(stdout, "Received:\n%s\n", message);
            fflush(stdout);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}
