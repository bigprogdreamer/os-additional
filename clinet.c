#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
int Socket (int domain, int type, int protocol)
{
  int res = socket (AF_INET, SOCK_STREAM, 0);
    if (res == -1)
    {
      printf ("we lost socket");
      exit (EXIT_FAILURE);
    }
    else
      return res;
}

int Connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int res = connect (sockfd, addr, addrlen);
  if (res == -1)
    {
      printf ("we lost connect");
	exit (EXIT_FAILURE);
    }
  return res;
}

int Inet_pton (int af, const char *src, void *dst)
{
  int res = inet_pton (af, src, dst);
  if (res == 0)
    {
      printf ("inet pthon failed no vailid network");
      exit (EXIT_FAILURE);
    }
  if (res == -1)
    {
      printf  ("inet pthon failed");
      exit (EXIT_FAILURE);
    }
  return res;
}

int main() {
    int fd = Socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in adr = {0};
    adr.sin_family = AF_INET;
    adr.sin_port = htons(34542);
    Inet_pton (AF_INET, "127.0.0.1", &adr.sin_addr);//прарсит строку засовывает чиселку
    Connect (fd, (struct sockaddr *) &adr, sizeof adr);
    int four_bytes = 0;
    for (;;)
      {
	int onserv =  write (fd, &four_bytes, sizeof(four_bytes));
	if (onserv == -1)
	  {
	    printf ("no write");
	    break;
	  }	  
	int nread = read(fd, &four_bytes, sizeof (four_bytes));
	if (nread == -1) {
	  printf("read failed");
	  break;
	}
	if (nread == 0) {
	  printf("EOF occured\n");
	}
	printf ("%d\r", four_bytes);
	four_bytes++;
      }
    close (fd);
    return 0;
}
