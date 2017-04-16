#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

struct sockaddr_in set_myaddr(int port)
{
    struct sockaddr_in saddr;
    saddr.sin_port = htons(port);
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    return saddr;
}

#define BLOCK_SIZE (64 * 1024)

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("uso: %s <porta_servidor>\n", argv[0]);
        return 0;
    }

    SSL_library_init();
    SSL_CTX *ctx;
    SSL_METHOD *metodo;
    SSL_load_error_strings();
    metodo = SSLv3_method();
    ctx = SSL_CTX_new(metodo);

    if ( ctx == NULL )
    {
        perror(" SSL_CTX_new()");
        return -1;
    }

    char *certificado = "NOME DO CERTIFICADO GERADO";

    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, certificado , SSL_FILETYPE_PEM) <= 0 )
    {
        perror("SSL_CTX_use_certificate_file()");
        return -1;
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, certificado, SSL_FILETYPE_PEM) <= 0 )
    {
        perror("SSL_CTX_use_PrivateKey_file()");
        return -1;
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }

    //SOCKET
    int lsfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsfd < 0)
    {
        perror("socket()");
        return -1;
    }
    //BIND
    struct sockaddr_in my_addr = set_myaddr(atoi(argv[1]));
    if (bind(lsfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
    {
        perror("bind()");
        close (lsfd);
        return -1;
    }
    //LISTEN
    if (listen(lsfd, 1024) < 0)
    {
        perror("listen()");
        close (lsfd);
        return -1;
    }
    unsigned char buff[BLOCK_SIZE];
    int csfd;
    struct sockaddr_in caddr;
    char file_name[1024];
    int nr, ns, fd, cod_resp;
    SSL *ssl;
    while (1)
    {
        socklen_t socklen = sizeof(struct sockaddr_in);
        //ACCEPT
        csfd = accept(lsfd, (struct sockaddr *)&caddr, &socklen);
        if (csfd < 0)
        {
            perror("accept()");
            continue;
        }
        printf("Conectado com %s:%d\n",
               inet_ntoa(caddr.sin_addr),
               ntohs(caddr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, csfd);      /* set connection socket to SSL state */

        bzero(file_name, 1024);

        if (SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
        {
            perror("SSL_accept()");
            continue;
        }

        //show certificados?



        //RECV or SSL_Read
        nr = SSL_read(ssl, file_name, 1024);
        if (nr < 0)
        {
            perror("recv(<file_name>)");
            close(csfd);
            continue;
        }
        fd = open(file_name, O_RDONLY);
        if (fd < 0)   // deu erro na abertura do aquivo solicitado
        {
            perror("open()");
            cod_resp = errno * -1;
            if (SSL_write(ssl, &cod_resp, sizeof(int)) < 0)
            {
                perror("send(<cod_resp>)");
                continue;
            }
        }
        else
        {
           // int SSL_write(SSL *ssl, const void *buf, int num);
            if (SSL_write(ssl, &fd, sizeof(int)) < 0)
            {
                perror("send(<fd>)");
                continue;
            }
        }
        do
        {
            bzero(buff, BLOCK_SIZE);
            nr = read(fd, buff, BLOCK_SIZE);
            if (nr < 0)
            {
                perror("read(<buff>)");
                close (csfd);
                continue;
            }
            ns = SSL_write(ssl, buff, nr);
            if (ns < 0)
            {
                perror("send(<buff>)");
                close(csfd);
                continue;
            }
        }
        while (nr > 0);
        SSL_free(ssl);
        close(csfd);
        close(fd);
        SSL_CTX_free(ctx);         /* release context */
    }
    return 0;
}
