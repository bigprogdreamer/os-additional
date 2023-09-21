#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include <ucontext.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <netinet/in.h>//для ip v4
#include <arpa/inet.h>
#include <netdb.h>	//hostent

typedef struct task_t {
  char  password[8];
  int from, to;
} task_t;

typedef bool (*password_handler_t) (task_t * task, void * arg);

typedef struct queue_t
{
  task_t queue[8];
  int head, tail;
  sem_t full, empty;
  pthread_mutex_t head_mutex, tail_mutex;
  bool canceled;
} queue_t;

typedef enum {
  RM_SINGLE,
  RM_MULTI,
  RM_ITER,
  RM_SERVER,
  RM_CLIENT,
} run_mode_t;

typedef enum {
  BM_ITER,
  BM_RECU,
  BM_RECU_ITER,
} brute_mode_t;

typedef struct config_t 
{
  int length;
  char * alph;
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  char * hash;
  int port;
  char * host; 
} config_t;

typedef struct m_worker_t
{
  queue_t queue;
  config_t * config;
  task_t found;
  volatile int unchecked_passwords_counter;
  pthread_mutex_t upc_mutex;
  pthread_cond_t sig_sem;
} m_worker_t;

typedef struct iter_state_t
{
  int idx[sizeof (((task_t*) NULL) ->password) / sizeof(((task_t*) NULL) -> password[0])];
  int alph_length_1;
  task_t * task;
  config_t * config;
} iter_state_t;

typedef struct rec_state_t
{
  char stack[1 << 12];
  ucontext_t main_context;
  ucontext_t rec_context;
  task_t * task;
  config_t * config;
  bool finished;
}rec_state_t;

typedef struct i_worker_t
{
  task_t * task;
  pthread_mutex_t state_mutex;
  config_t * config;
  task_t found;
  volatile bool finished;
  union {
    iter_state_t iter_state[0];
    rec_state_t rec_state[0];
  };
} i_worker_t;

typedef struct check_password_context_t
{
  char * hash;
  struct crypt_data cd;
} check_password_context_t;

typedef struct server_context_t
{
  int socket;
  m_worker_t m_worker;
  pthread_mutex_t socket_mutex;
  bool finished;
} server_context_t;

void queue_init (queue_t * queue)
{
  queue->canceled = false;
  queue->tail = 0;
  queue->head = 0;
  pthread_mutex_init (&queue->head_mutex, NULL);
  pthread_mutex_init (&queue->tail_mutex, NULL);
  sem_init (&queue->full, 0, 0);
  sem_init (&queue->empty, 0, sizeof (queue->queue) / sizeof (queue->queue[0]));  
}

bool queue_push (queue_t * queue, task_t * task)
{
  sem_wait (&queue->empty);
  if (queue->canceled)
    {
      sem_post (&queue->empty);
      return false;
    }
  pthread_mutex_lock (&queue->tail_mutex);
  queue->queue[queue->tail] = *task;
  if (++queue->tail >= sizeof (queue->queue) / sizeof (queue->queue[0]))
    queue->tail = 0;
  pthread_mutex_unlock (&queue->tail_mutex); 
  sem_post (&queue->full);
  return true;
}

bool queue_pop (queue_t * queue, task_t * task)
{
  sem_wait (&queue->full);
  if (queue->canceled)
    {
      sem_post (&queue->full);
      return false;
    }
  pthread_mutex_lock (&queue->head_mutex);
  *task = queue->queue[queue->head];
  if (++queue->head >= sizeof (queue->queue) / sizeof (queue->queue[0]))
    queue->head = 0;
  pthread_mutex_unlock (&queue->head_mutex);         
  sem_post (&queue->empty);
  return true;
}

void queue_cancel (queue_t * queue)
{
  queue->canceled = true;
  sem_post (&queue->full);
  sem_post (&queue->empty);
}

bool check_password (task_t * task, void * arg)
{
  check_password_context_t * check_password_context = arg;
  return !strcmp (check_password_context->hash, crypt_r (task->password,
							 check_password_context->hash,
							 &check_password_context->cd));
}

bool brute_recc (task_t * task, config_t * config, password_handler_t password_handler,
		 void * arg, int pos)
{
  int i;
  if (pos == task->to)
    {
      if (password_handler (task, arg))
	{
	  return true;
	}
    }
  else
    for (i = 0; config->alph[i]; ++i)
      {
	task->password[pos] = config->alph[i];
	if (brute_recc (task, config, password_handler, arg, pos + 1))
	  return true;
      }
  return false;
}

bool brute_rec (task_t * task, config_t * config, password_handler_t password_handler, void * arg)
{
  return brute_recc (task, config, password_handler, arg, task->from);
}

bool rec_password_handler (task_t * task, void * arg)
{
  rec_state_t * rec_state = arg;
  swapcontext (&rec_state->rec_context, &rec_state->main_context);
  return false;
}

void brute_rec_wrapper (rec_state_t * rec_state)
{
  brute_rec (rec_state->task, rec_state->config, rec_password_handler, rec_state);
  rec_state->finished = true;
}

void rec_state_init (rec_state_t * rec_state, task_t * task, config_t * config)
{
  rec_state->finished = false;
  rec_state->task = task;
  rec_state->config = config;
  getcontext (&rec_state->rec_context);//инцилизирует внутренние поля
  rec_state->rec_context.uc_link = &rec_state->main_context;
  rec_state->rec_context.uc_stack.ss_sp = rec_state->stack;
  rec_state->rec_context.uc_stack.ss_size = sizeof(rec_state->stack);
  makecontext (&rec_state->rec_context, (void (*) (void)) brute_rec_wrapper, 1, rec_state);
  swapcontext (&rec_state->main_context, &rec_state->rec_context);
}

bool rec_state_next (rec_state_t * rec_state)
{
  if (!rec_state->finished)
    swapcontext (&rec_state->main_context, &rec_state->rec_context);
  return rec_state->finished;
}

bool brute_rec_iter (task_t * task, config_t * config, password_handler_t password_handler, void * arg)
{
  rec_state_t rec_state;
  rec_state_init (&rec_state, task, config);
  for (;;)
    {
      if (password_handler (task, arg))
	return true;
      if (rec_state_next (&rec_state))
	break;
    }
  return false;
}

void iter_state_init (iter_state_t * iter_state, task_t * task, config_t * config)
{
  int i;
  iter_state->task = task;
  iter_state->config = config;
  iter_state->alph_length_1 = strlen (config->alph) - 1;
  for (i = task->from; i < task->to; ++i)
    {
      iter_state->idx[i] = 0;
      task->password[i] = config->alph[0];
    }
}

bool iter_state_next (iter_state_t * iter_state)
{
  int i;
  task_t * task = iter_state->task;
  for (i = task->to - 1; (i >= task->from) && (iter_state->idx[i] == iter_state->alph_length_1); i--)
    {
      iter_state->idx[i] = 0;
      task->password[i] = iter_state->config->alph[0];
    }
  if (i < task->from)
    return true;
  task -> password[i] = iter_state->config->alph[++iter_state->idx[i]];
  return false;
}

bool brute_iter (task_t * task, config_t * config, password_handler_t password_handler, void * arg)
{
  iter_state_t iter_state;
  iter_state_init (&iter_state, task, config);
  for (;;)
    {
      if (password_handler (task, arg))
	return true;
      if (iter_state_next (&iter_state))
	break;
    }
  return false;
}

void parse_params (config_t * config,  int argc, char * argv[])
{
  int opt;
  while ((opt = getopt (argc, argv, "a:l:rismteh:c:pou:d:")) != -1)
    {
      switch (opt)
	{
	case 'a':
	  config->alph = optarg;
	  break;
	case 'l':
	  config->length = atoi(optarg);
	  break;
	case 'r':
	  config->brute_mode = BM_RECU;
	  break;
	case 'i':
	  config->brute_mode = BM_ITER;
	  break;
	case 'e':
	  config->brute_mode = BM_RECU_ITER;
	  break;
	case 'h':
	  config->hash = optarg;
	  break;
	case 's':
	  config->run_mode = RM_SINGLE;
	  break;
	case 'm':
	  config->run_mode = RM_MULTI;
	  break;
	case 't':
	  config->run_mode = RM_ITER;
	  break;
	case 'c':
	  printf ("hash for '%s' = '%s' \n", optarg, crypt (optarg, "aa"));
	  exit(1);
	  break;
	case 'o':
	  config->run_mode = RM_CLIENT;
	  break;
	case 'u':
	  config->port = atoi(optarg);
	  break;
	case 'd':
	  config->host = optarg;
	  break;
	case 'p':
	  config->run_mode = RM_SERVER;
	  break;
	}
    }
}

int Socket (int domain, int type, int protocol)
{
  int res = socket (AF_INET, SOCK_STREAM, 0);
    if (res == -1)
    {
      printf ("we lost socket\n");
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
      printf ("we lost bind\n");
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
      printf("we lost listen\n");
      exit (EXIT_FAILURE);
    }
  return res;
}

void m_worker_init (m_worker_t * m_worker, config_t * config)
{
  pthread_mutex_init (&m_worker->upc_mutex, NULL);
  pthread_cond_init (&m_worker->sig_sem, NULL);
  m_worker->unchecked_passwords_counter = 0;
  m_worker->found.password[0] = 0;
  queue_init (&m_worker->queue);
  m_worker->config = config; 
}

void * handle_client (void * arg)
{
  printf("line%d \n",__LINE__);
  server_context_t * server_context = arg;
  int client_socket = server_context->socket;
  pthread_mutex_unlock (&server_context->socket_mutex);
  task_t task;
  int sent_bytes;
  int recieved_bytes;
  sent_bytes = write (client_socket, server_context->m_worker.config->hash,
	 sizeof (((struct crypt_data *) 0)->output));
  printf("line%d \n",__LINE__);
  if (sent_bytes <= 0)
    {
      printf ("can't send files on client");
      goto close_socket;
    }
  printf("line%d \n",__LINE__);
  int size = strlen(server_context->m_worker.config->alph);
  printf("line%d \n",__LINE__);
  sent_bytes = write (client_socket, &size, sizeof (size));
  printf("line%d \n",__LINE__);
  if (sent_bytes <= 0)
    {
      printf ("can't send files on client");
      goto close_socket;
    }
  sent_bytes = write (client_socket, server_context->m_worker.config->alph,
		      sizeof (char) * size);
  printf("line%d \n",__LINE__);
  if (sent_bytes <= 0)
    {
      printf ("can't send files on client");
      goto close_socket;
    }
  for (;;)
    {
      if (server_context->finished)
	break;
      if (!queue_pop (&server_context->m_worker.queue, &task))
	break;
      sent_bytes = write (server_context->socket, &task, sizeof (task));
      printf("line%d \n",__LINE__);
      if (sent_bytes <= 0)
	{
	  printf ("can't send files on client");
	  goto close_socket;
	}
      recieved_bytes = read (client_socket, &task.password, sizeof (task.password));
      if (recieved_bytes <= 0)
	{
	  printf ("can't get files from client");
	  goto close_socket;
	}
      if (task.password[0])
	{
	  queue_cancel (&server_context->m_worker.queue);
	  server_context->m_worker.found = task;
	}
      pthread_mutex_lock (&server_context->m_worker.upc_mutex);
      server_context->m_worker.unchecked_passwords_counter--;
      pthread_mutex_unlock (&server_context->m_worker.upc_mutex);
      if (server_context->m_worker.unchecked_passwords_counter == 0)
	pthread_cond_signal (&server_context->m_worker.sig_sem);
    }

 close_socket:
  close (client_socket);
  return 0;
}

bool m_task_hadler (task_t * task, void * arg)
{
  m_worker_t * m_worker = arg;
  pthread_mutex_lock (&m_worker->upc_mutex);
  m_worker->unchecked_passwords_counter++;
  pthread_mutex_unlock (&m_worker->upc_mutex);
  if (!queue_push (&m_worker->queue, task))
    return true;
  return m_worker->found.password[0];
}

void m_worker_generator (m_worker_t * m_worker, task_t * task)
{
  switch (m_worker->config->brute_mode)
    {
    case BM_ITER :
      brute_iter (task, m_worker->config, m_task_hadler, m_worker);
      break;
    case BM_RECU :
      brute_rec (task, m_worker->config, m_task_hadler, m_worker);
      break;
    case BM_RECU_ITER :
      brute_rec_iter (task, m_worker->config, m_task_hadler, m_worker);
      break;
      
    default:
      break;
    }
  pthread_mutex_lock (&m_worker->upc_mutex);
  while (m_worker->unchecked_passwords_counter != 0)
    pthread_cond_wait (&m_worker->sig_sem, &m_worker->upc_mutex);
  pthread_mutex_unlock (&m_worker->upc_mutex);

}

void * client_accepting (void * arg)
{
 printf("line%d \n",__LINE__);
 server_context_t * server_context = arg;
 int server_socket = server_context->socket;
 pthread_mutex_init (&server_context->socket_mutex, NULL);
 for (;;)
    {
      pthread_t id;
      printf("line%d \n",__LINE__);
      pthread_mutex_lock (&server_context->socket_mutex);
      printf("line%d \n",__LINE__);
      server_context->socket = accept (server_socket, NULL, NULL);
      printf("line%d \n",__LINE__);
      if (server_context->socket == -1)
	{
	  printf ("accept failed\n");
	  return NULL;
	}
      if (pthread_create (&id, NULL, handle_client, server_context))
	pthread_mutex_unlock (&server_context->socket_mutex);
    }
 return NULL;
}

void run_client (task_t * task, config_t * config)
{
    int fd = Socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in adr = {0};
    adr.sin_family = AF_INET;
    adr.sin_port = htons(config->port);
    if (config->host)
      {
	struct hostent *he = gethostbyname (config->host);
	if (he == NULL)
	  {
	    printf ("can't resolve host name");
	    return;
	  }
	adr.sin_addr = *((struct in_addr *) he->h_addr_list[0]);
      }
    else
      adr.sin_addr.s_addr = htonl(INADDR_ANY);
    int connect_status = connect (fd, (struct sockaddr *) &adr, sizeof adr);
    if (!connect_status)
      {
	printf  ("no connection\n");
	goto clos_socket;
      }
 clos_socket:
    close (fd);
}

void run_single (task_t * task, config_t * config)
{
  bool found = false;
  check_password_context_t check_password_context = {
   .hash = config->hash,
   .cd = { .initialized = 0 }
  };

  switch (config->brute_mode)
    {
    case BM_ITER :
      found = brute_iter (task, config, check_password, &check_password_context);
      break;
    case BM_RECU :
      found = brute_rec (task, config, check_password, &check_password_context);
      break;
    case BM_RECU_ITER :
      found = brute_rec_iter (task, config, check_password, &check_password_context);
      break;
    }
  if (!found)
    task->password[0] = 0;
}

void * worker_multi (void * arg)
{
  m_worker_t * m_worker = arg;
  config_t * config = m_worker->config;
  task_t task;
  check_password_context_t check_password_context = {
   .hash = m_worker->config->hash,
   .cd = { .initialized = 0 }
  };
  
  for (;;)
    {
      if (!queue_pop (&m_worker->queue, &task))
	break;
      task.to = task.from;
      task.from = 0;
      bool found = false;
      switch (config->brute_mode)
	{
	case BM_ITER :
	  found = brute_iter (&task, config, check_password, &check_password_context);
	  break;
	case BM_RECU :
	  found = brute_rec (&task, config, check_password, &check_password_context);
	  break;
	case BM_RECU_ITER :
	  found = brute_rec_iter (&task, config, check_password, &check_password_context);
	  break;
	default:
	   break;
	}
      if (found)
	m_worker->found = task; 
      pthread_mutex_lock (&m_worker->upc_mutex);
      m_worker->unchecked_passwords_counter--;
      pthread_mutex_unlock (&m_worker->upc_mutex);
      if (m_worker->unchecked_passwords_counter == 0)
	pthread_cond_signal (&m_worker->sig_sem);
    }
  return NULL;
}

void run_multi (task_t * task, config_t * config)
{
  int n_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  int i;
  pthread_t ids[n_cpu];
  m_worker_t m_worker;
  m_worker_init (&m_worker, config);
  task->from = 2;
  for (i = 0; i < n_cpu; i++)
    {
      pthread_create (&ids[i], NULL, worker_multi, &m_worker);
    }
  m_worker_generator (&m_worker, task);
  for (i = 0; i < n_cpu; i++)
    {
      pthread_cancel (ids[i]);
      pthread_join (ids[i], NULL); 
    }
  *task = m_worker.found;
}

void * worker_iter (void * arg)
{
  i_worker_t * i_worker = arg;
  iter_state_t * iter_state = i_worker->iter_state;
  rec_state_t * rec_state = i_worker->rec_state;
  task_t task;
  config_t * config = i_worker->config;
  check_password_context_t check_password_context = {
   .hash = i_worker->config->hash,
   .cd = { .initialized = 0 }
  };                                                                          
 
  bool finished = i_worker->finished;
  for (;;)
    {
      pthread_mutex_lock (&i_worker->state_mutex);
      if (!i_worker->finished)
	{
	  switch (config->brute_mode)
	    {
	    case BM_ITER :
	      task = *iter_state->task;//почему было написано  *&
	      finished = iter_state_next (iter_state);
	      break;
	    case BM_RECU:
	    case BM_RECU_ITER :
	      task = *rec_state->task;//почему было написано  *&
	      finished = rec_state_next (rec_state);
	      break;
	    }
	}
      pthread_mutex_unlock (&i_worker->state_mutex);
      task.to = task.from;
      task.from = 0;
      if (i_worker->finished)
	break;
      bool found = false;
      switch (config->brute_mode)
	{
	case BM_ITER :
	  found = brute_iter (&task, config, check_password, &check_password_context);
	  break;
	case BM_RECU :
	  found = brute_rec (&task, config, check_password, &check_password_context);
	  break;
	case BM_RECU_ITER :
	  found = brute_rec_iter (&task, config, check_password, &check_password_context);
	  break;
	default:
	  break;
	}
      if (found == true)
	{	  
	  i_worker->found = task;
	  finished = true;
	}
      if (finished)
	i_worker->finished = true;
    }
  return NULL;
}

void run_iter (task_t * task, config_t * config)
{
  i_worker_t * i_worker = NULL; 
  int n_cpu = sysconf (_SC_NPROCESSORS_ONLN);
  pthread_t ids[n_cpu];
  int i;
  
  task->from = 2; 
  switch (config->brute_mode)
    {
    case BM_ITER :
      i_worker = alloca (sizeof (*i_worker->iter_state) + sizeof (*i_worker));
      iter_state_init (i_worker->iter_state, task, config);
      break;
    case BM_RECU:
    case BM_RECU_ITER:
      i_worker = alloca (sizeof (*i_worker->rec_state) + sizeof (*i_worker));
      rec_state_init (i_worker->rec_state, task, config);
      break;
    }
  i_worker->found.password[0] = 0;
  i_worker->finished = false;
  i_worker->config = config;
  pthread_mutex_init (&i_worker->state_mutex, NULL);

  for (i = 0; i < n_cpu; i++)
    pthread_create (&ids[i], NULL, worker_iter, i_worker);
  
  for (i = 0; i < n_cpu; i++)
    pthread_join (ids[i], NULL); 
  *task = i_worker->found;
}

void run_server (task_t * task, config_t * config)
{
  server_context_t server_context;
  pthread_t id;
  int server = Socket (AF_INET, SOCK_STREAM, 0);
  server_context.socket = server;
  server_context.finished = false;
  m_worker_init (&server_context.m_worker, config);
  struct sockaddr_in adr = {0}; //задать адресс по протоколу ipv4
  adr.sin_family = AF_INET;//интернет
  adr.sin_port = htons (config->port); //host to network short  //от хсота к сети
  Bind (server, (struct sockaddr*) &adr, sizeof adr);
  Listen (server, 3);//очердь максимум из 3 штук
  printf("line%d \n",__LINE__);
  pthread_create (&id, NULL, client_accepting, &server_context);
  printf("line%d \n",__LINE__);
  m_worker_generator (&server_context.m_worker, task);
  printf("line%d \n",__LINE__);
  //привязка сокета к адресусоздаем серверный сокет
  close (server);
}

int main (int argc, char *argv[])
{
  config_t config =
    {
      .length = 3,
      .alph = "abc",
      .brute_mode = BM_ITER,
      .hash = "acOKe6jv8KKZU",
      .run_mode = RM_SINGLE,
      .port = 3245
    };
  parse_params (&config, argc, argv);
  task_t task;
  task.from = 0;
  task.to = config.length;
  task.password[config.length] = 0;
  switch (config.run_mode)
    {
    case RM_SINGLE:
      run_single (&task, &config);
      break;
    case RM_MULTI:
      run_multi (&task, &config);
      break;
    case RM_ITER:
      run_iter (&task, &config);
      break;
    case RM_SERVER:
      run_server (&task, &config);
      break;
    case RM_CLIENT:
      run_client (&task, &config);
      break;
     
    }
  if (task.password[0])
    printf ("%s\n", task.password);
  else
    printf ("no match\n");
  return 0;
}
