#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#define MSG_LEN (64 *1024)

struct sockaddr_in server_addr(int port, char *addr)
{
    struct sockaddr_in saddr;
    saddr.sin_port = htons(port);
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(addr);
    return saddr;
}

int main(int argc, char **argv)
{

    SSL_library_init();
    SSL_METHOD *metodo;
    SSL_CTX *ctx;
    SSL *ssl;


    if (argc != 5)
    {
        printf("uso: %s <ip_servidor> <porta_servidor> <arquivo_servidor> <arquivo_destino>\n", argv[0]);
        return 0;
    }




   // OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();
    metodo = SSLv3_method();
    ctx = SSL_CTX_new(metodo);   /* Create new context */
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        return -1;
    }

    int sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sfd < 0)
    {
        perror("socket()");
        return -1;
    }

    struct sockaddr_in saddr = server_addr(atoi(argv[2]), argv[1]);

    if (connect(sfd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        perror("connect()");
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sfd);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == -1 )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else{

        int ns, nr;
        ns =  SSL_write(ssl, argv[3], strlen(argv[3]));
        if (ns < 0)
        {
            perror("write(<arquivo_servidor>)");
            close(sfd);
            SSL_free(ssl);
            return -1;
        }

        int cod_resp;
        nr =  SSL_read(ssl, &cod_resp, sizeof(int));
        if (nr < 0)
        {
            perror("read(cod_resp)");
            close(sfd);
            SSL_free(ssl);
            return -1;
        }

        if (cod_resp < 0)
        {
            printf("sevidor: %s\n", strerror(cod_resp*-1));
            close (sfd);
            SSL_free(ssl);
            return -1;
        }

        int fd;
        fd = open(argv[4], O_CREAT | O_RDWR | O_APPEND, 0644);
        if (fd < 0)
        {
            perror("open()");
            close (sfd);
            SSL_free(ssl);
            return -1;
        }

        void *buff = calloc(1, MSG_LEN);
        if (!buff)
        {
            perror("calloc()");
            close (sfd);
            SSL_free(ssl);
            return -1;
        }
        int nw;
        do
        {
            bzero(buff, MSG_LEN);
            nr = SSL_read(ssl, buff, MSG_LEN);
            if (nr > 0)
            {
                nw = write(fd, buff, nr);
                if (nw < 0)
                {
                    perror("write(<buff>)");
                    close(sfd);
                    close(fd);
                    SSL_free(ssl);
                    return -1;
                }
            }
            else
            {
                perror("recv(<buff>)");
                close(sfd);
                close(fd);
                SSL_free(ssl);
                return -1;
            }
        }
        while (nr > 0);

    }
    close(sfd);
    close(fd);
    SSL_CTX_free(ctx); 
    return 0;
}
