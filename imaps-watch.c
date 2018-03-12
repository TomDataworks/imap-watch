#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>

#include <openssl/ssl.h>

#define INI_USE_STACK
#include "ini.h"

#define BUFSZ 128
#define MAX_TAG_VALUE 999        // About a week with 9 minute idle timeout

#define XRECV_TIMEOUT (-1)       // Timeout on socket
#define XRECV_CLOSED  (-2)       // Socket was closed abruptly

struct globals {
  char * user;
  char * pass;
  char * mailbox;
  char * host;
  char * port;
  int keepalive;
  int resync;
  char * command;
} globals = {
  .user = NULL,
  .pass = NULL,
  .mailbox = "INBOX",
  .host = "imap.gmail.com",
  .port = "imaps",
  .keepalive = 300,
  .command = "/usr/local/bin/mbsync gmail",
  .resync = 6
};

unsigned int tag = 0;

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    struct globals* config = (struct globals*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("imaps", "user")) {
        config->user = strdup(value);
    } else if (MATCH("imaps", "pass")) {
        config->pass = strdup(value);
    } else if (MATCH("imaps", "mailbox")) {
        config->mailbox = strdup(value);
    } else if (MATCH("imaps", "host")) {
        config->host = strdup(value);
    } else if (MATCH("imaps", "port")) {
        config->port = strdup(value);
    } else if (MATCH("imaps", "keepalive")) {
        config->keepalive = atoi(value);
    } else if (MATCH("imaps", "resync")) {
        config->resync = 6;
    } else if (MATCH("sync", "command")) {
        config->command = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

int create_socket(char hostname[], char port[]);
static unsigned long parse_message_id(char * buffer);

static char reply[BUFSZ];

int xrecv(SSL* ssl) {
  int sockfd = SSL_get_fd(ssl);
  struct timeval tv;
  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(sockfd, &read_fds);

  tv.tv_sec  = globals.keepalive;
  tv.tv_usec = 0;
  ssize_t received;
  int message = XRECV_TIMEOUT;

  int rv = select(sockfd + 1, &read_fds, NULL, NULL, &tv);
  if (rv < 0) { perror("select"); exit(EXIT_FAILURE); }

  if (rv > 0 && FD_ISSET(sockfd, &read_fds)) {
    message = 0;
    do {
      memset(reply, 0, BUFSZ);
      received = SSL_read(ssl, reply, BUFSZ - 1);
      if (received <= 0) { return XRECV_CLOSED; }
      fputs(reply, stdout);
      fflush(stdout);
      if (message == 0) {
        message = parse_message_id(reply);
      }
    } while(reply[received-1] != '\n');
  }

  return message;

}

static void ni_imap_cmd(SSL* ssl, unsigned short need_tag, const char *fmt, ...){
  char command[256];
  char buffer[256];

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, ap);
  va_end(ap);

  if(need_tag){
    snprintf(command, sizeof(command), "%04d %s\r\n", ++tag, buffer);
  } else {
    snprintf(command, sizeof(command), "%s\r\n", buffer);
  }

  SSL_write(ssl, command, strlen(command));
  printf("%% %s", command);
  fflush(stdout);

  xrecv(ssl);
}

static void ni_login(SSL *ssl){
  ni_imap_cmd(ssl, 1, "LOGIN \"%s\" \"%s\"", globals.user, globals.pass);
  ni_imap_cmd(ssl, 1, "SELECT \"%s\"", globals.mailbox);
}

static unsigned long parse_message_id(char * buffer){
  unsigned long toret = 0;

  sscanf(buffer, "* %lu EXISTS", &toret);

  return toret;
}

static void check_messages() {
  printf("; forking %s...\n", globals.command);
  fflush(stdout);
  int wstatus;

  pid_t pid = fork();
  if (pid == 0) {
    execl("/bin/sh", "sh", "-c", globals.command);
    exit(EXIT_SUCCESS);
  } else {
    waitpid(pid, &wstatus, 0);
    printf("; child %d returned with status %d.\n", pid, wstatus);
    fflush(stdout);
  }
}

static void ni_idle(SSL *ssl){
  int syncs = 0;

  ni_imap_cmd(ssl, 1, "IDLE");

  while(tag < MAX_TAG_VALUE) {
    int rv = xrecv(ssl);

    if (rv == XRECV_TIMEOUT) {
      printf("; timeout\n");
      fflush(stdout);
      ni_imap_cmd(ssl, 0, "DONE");
      if (globals.resync > 0 && syncs >= globals.resync) {
        printf("; checking messages anyway, too many timeouts.\n");
        fflush(stdout);
        check_messages();
        syncs = 0;
      }
      ni_imap_cmd(ssl, 1, "IDLE");
    } else if (rv == XRECV_CLOSED) {
      printf("; ssl read failure, attempting reconnect.\n");
      fflush(stdout);
      tag = 0;
      return;
    } else if(rv > 0) {
      ni_imap_cmd(ssl, 0, "DONE");
      check_messages();
      ni_imap_cmd(ssl, 1, "IDLE");
    }

  }

  // clear the tag to signal we left cleanly, want to reconnect
  tag = 0;
}

static void notifidle(SSL *ssl){
  ni_login(ssl);
  ni_idle(ssl);
}

int main (int argc, char * const argv[]){
  int opt;
  char* file = NULL;

  while ( (opt = getopt(argc, argv, "c:")) != -1 ){
    switch (opt){
      case 'c':
        file = strdup(optarg);
        break;
    }
  }

  if (file == NULL) {
    char* home = getenv("HOME");
    char* conf = getenv("XDG_CONFIG_HOME");
    char path[512];
    if (conf)
      snprintf(path, sizeof(path), "%s/%s", conf, "imaps-watch.ini");
    else
      snprintf(path, sizeof(path), "%s/.config/%s", home, "imaps-watch.ini");
    file = strdup(path);
  }

  if (ini_parse(file, handler, &globals) < 0) {
    fprintf(stderr, "USAGE: %s [-c <config>]\n", argv[0]);
    fprintf(stderr, "Can't load configuration '%s'\n", file);
    exit(EXIT_FAILURE);
  }

  printf("Loaded configuration from '%s'\n", file);

  /* ---------------------------------------------------------- *
   * Basic openssl data structures                              *
   * ---------------------------------------------------------- */
  X509             *cert = NULL;
  const SSL_METHOD *method;
  SSL_CTX          *ctx;
  SSL              *ssl;
  int server = 0;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work   *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();

  /* ---------------------------------------------------------- *
   * Initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
    fprintf(stderr, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set the version-flexible SSL/TLS method                    *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try connection only if our tag number is zero, i.e. we are *
   * just starting out or we have been connected too long, or   *
   * we are handling a recoverable error.                       *
   * ---------------------------------------------------------- */
  while (tag == 0) {

    /* ---------------------------------------------------------- *
     * Try to create a new SSL context                            *
     * ---------------------------------------------------------- */
    if ( (ctx = SSL_CTX_new(method)) == NULL)
    fprintf(stderr, "Unable to create a new SSL context structure.\n");

    /* ---------------------------------------------------------- *
     * Require TLSv1.1 or TLSv1.2                                 *
     * ---------------------------------------------------------- */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* ---------------------------------------------------------- *
     * Create new SSL connection state object                     *
     * ---------------------------------------------------------- */
    ssl = SSL_new(ctx);

    /* ---------------------------------------------------------- *
     * Make the underlying TCP socket connection                  *
     * ---------------------------------------------------------- */
    server = create_socket(globals.host, globals.port);
    if(server != 0)
    printf("Successfully made the TCP connection to: %s.\n", globals.host);

    /* ---------------------------------------------------------- *
     * Attach the SSL session to the socket descriptor            *
     * ---------------------------------------------------------- */
    SSL_set_fd(ssl, server);

    /* ---------------------------------------------------------- *
     * Try to SSL-connect here, returns 1 for success             *
     * ---------------------------------------------------------- */
    if ( SSL_connect(ssl) != 1 )
      fprintf(stderr, "Error: Could not build a SSL session to: %s.\n", globals.host);
    else
      printf("Successfully enabled SSL/TLS session to: %s.\n", globals.host);

    /* ---------------------------------------------------------- *
     * Get the remote certificate into the X509 structure         *
     * ---------------------------------------------------------- */
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
      fprintf(stderr, "Error: Could not get a certificate from: %s.\n", globals.host);
    else
      printf("Retrieved the server's certificate from: %s.\n", globals.host);

    /* ---------------------------------------------------------- *
     * Call the idle notification routines                        *
     * -----------------------------------------------------------*/
    notifidle(ssl);

    /* ---------------------------------------------------------- *
     * Free the structures we don't need anymore                  *
     * -----------------------------------------------------------*/
    SSL_free(ssl);
    close(server);
    X509_free(cert);
    SSL_CTX_free(ctx);
    printf("Finished SSL/TLS connection with server: %s.\n", globals.host);

  }

  return 0;
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char hostname[], char service[]) {
  int sockfd;

  struct addrinfo hints, *servinfo, *p;
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
  hints.ai_socktype = SOCK_STREAM;


  /* ---------------------------------------------------------- *
   * Get valid addresses for host name                          *
   * -----------------------------------------------------------*/
  if ((rv = getaddrinfo(hostname, service, &hints, &servinfo)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      exit(EXIT_FAILURE);
  }

  /* ---------------------------------------------------------- *
   * Loop through all results and connect to first valid one    *
   * -----------------------------------------------------------*/
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1) {
        perror("socket");
        continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        perror("connect");
        close(sockfd);
        continue;
    }

    freeaddrinfo(servinfo);
    return sockfd;
  }

  return -1;

}

/* vim: set ts=2 sw=2 et */
