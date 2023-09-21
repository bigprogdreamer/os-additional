#include <sys/types.h>  
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>//для ip v4
#include <arpa/inet.h>
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

int Bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  int res = bind (sockfd, addr, addrlen);
    if (res != 0)
    {
      printf ("we lost bind");
      exit (EXIT_FAILURE);
    }
    else
      return res;
}
int Listen (int sockfd, int backlog)
{
  int res = listen (sockfd, backlog);
  if (res == -1)
    {
      printf("we lost listen");
      exit (EXIT_FAILURE);
    }
  return res;
}

int Accept (int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int client_accept = accept (sockfd, NULL, NULL); //файловый дескриптор
  if (client_accept == -1)
    {
      printf ("accept failed");
      exit (EXIT_FAILURE);
    }
  return client_accept;
}
int main ()
{
  int server = Socket (AF_INET, SOCK_STREAM, 0);
  //привязка сокета к адресусоздаем серверный сокет
  struct sockaddr_in adr = {0}; //задать адресс по протоколу ipv4
  adr.sin_family = AF_INET;//интернет
  adr.sin_port = htons (34542); //host to network short  //от хсота к сети
  Bind (server, (struct sockaddr*) &adr, sizeof adr);
  Listen (server, 3);//очердь максимум из 3 штук
  for (;;)
    {
      int client_accept = Accept (server, NULL, NULL); //файловый дескриптор через него можно общаться с клиентом
      int four_bytes = 8;
      for (;;)
	{
	  int onserver = read (client_accept, &four_bytes, sizeof (four_bytes));
	  if (onserver <= 0)
	    {
	      printf ("no read");
	      break;
	    }
      
	  onserver = write (client_accept, &four_bytes, sizeof(four_bytes));
	  if (onserver <= 0)
	    {
	      printf ("no write");
	      break;
	    }
	  // printf("%d",onserver);
	}
      printf ("client disconnccted, waiting for next client\n");
      close (client_accept);
    }
  close (server);
  
  return 0;
}
