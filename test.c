#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
void * routine ()
{
  printf("test from \n");
}
int main (int argc, char* argv[])
{
  pthread t1;
  pthread_create (&t1,NULL,&routine, NULL);
  pthread_join (t1,NULL);
  return 0;
}
