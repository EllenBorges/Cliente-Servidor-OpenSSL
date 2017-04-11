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
        bzero(file_name, 1024);
        //RECV
        nr = recv(csfd, file_name, 1024, 0);
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
            if (send(csfd, &cod_resp, sizeof(int), 0) < 0)
            {
                perror("send(<cod_resp>)");
                continue;
            }
        }
        else
        {
            if (send(csfd, &fd, sizeof(int), 0) < 0)
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
            ns = send(csfd, buff, nr, 0);
            if (ns < 0)
            {
                perror("send(<buff>)");
                close(csfd);
                continue;
            }
        }
        while (nr > 0);
        close(csfd);
        close(fd);
    }
    return 0;
}
