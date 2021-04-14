#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>
#include "http.h"
#include "logger.h"
#include "timer.h"

#define LISTENQ 1024

#define ACCEPT 0
#define READ 1
#define WRITE 2

#define MAX_MESSAGE_LEN 4096

#define IO_URING_QUEUE_DEPTH 4096

void add_request_accept(struct io_uring *ring, int sockfd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags)
{
    printf("Add accept\n");
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    
	io_uring_prep_accept(sqe, sockfd, client_addr, client_len, 0);

	http_request_t req = {
	.fd = sockfd,
	.event_type = ACCEPT,
	};
	io_uring_sqe_set_data(sqe, &req);

	// io_uring_sqe_set_flags(sqe, flags);
	io_uring_submit(ring);
}

void add_request_read(struct io_uring *ring, int fd, void *buf, unsigned msg_size, unsigned flags, char *root)
{
    printf("Add read\n");
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	
	io_uring_prep_recv(sqe, fd, buf, msg_size, 0);
	
	http_request_t req;
	init_http_request(&req, fd, root);
	req.event_type = READ;
	io_uring_sqe_set_data(sqe, &req);
	
	// io_uring_sqe_set_flags(sqe, flags);
	io_uring_submit(ring);
}

void add_request_write(struct io_uring *ring, int fd, void *buf, unsigned msg_size, unsigned flags)
{
    printf("Add write\n");
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	
	io_uring_prep_send(sqe, fd, buf, msg_size, 0);

	http_request_t req = {
	.fd = fd,
	.event_type = WRITE,
	};
	io_uring_sqe_set_data(sqe, &req);
	
	// io_uring_sqe_set_flags(sqe, flags);
	io_uring_submit(ring);
}

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminate "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval,
                   sizeof(int)) < 0)
        return -1;

    /* Listenfd will be an endpoint for all requests to given port. */
    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;

    return listenfd;
}

/* set a socket non-blocking. If a listen socket is a blocking socket, after
 * it comes out from epoll and accepts the last connection, the next accpet
 * will block unexpectedly.
 */
static int sock_set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    int s = fcntl(fd, F_SETFL, flags);
    if (s == -1) {
        log_err("fcntl");
        return -1;
    }
    return 0;
}

/* TODO: use command line options to specify */
#define PORT 8081
#define WEBROOT "./www"

int main()
{
    char buf[MAX_MESSAGE_LEN];
    /* when a fd is closed by remote, writing to this fd will cause system
     * send SIGPIPE to this process, which exit the program
     */
    if (sigaction(SIGPIPE,
                  &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0},
                  NULL)) {
        log_err("Failed to install sigal handler for SIGPIPE");
        return 0;
    }

    int listenfd = open_listenfd(PORT);

    //timer_init();
	
	struct io_uring ring;

	if (io_uring_queue_init(IO_URING_QUEUE_DEPTH, &ring, 0) != 0) {
	    printf("io_uring init failed.\n");
		return EXIT_FAILURE;
	}
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
    
	printf("Web server started.\n");
	
	add_request_accept(&ring, listenfd, (struct sockaddr *)&client_addr, &client_len, 0);

	while (1) {
	    io_uring_submit_and_wait(&ring, 1);
		struct io_uring_cqe *cqe;
		unsigned head;
		unsigned count = 0;

		io_uring_for_each_cqe(&ring, head, cqe) {
		    ++count;
			http_request_t *request = io_uring_cqe_get_data(cqe);
			int event_type = request->event_type;
			printf("event type = %d\n", event_type);
			switch (event_type) {
			    case ACCEPT:
					add_request_accept(&ring, listenfd, (struct sockaddr *)&client_addr, &client_len, 0);
					int clientfd = cqe->res; /* cqe->res might be client fd*/
					if (clientfd >= 0) { /* TODO: check contain "=" or not */
				        add_request_read(&ring, clientfd, buf, MAX_MESSAGE_LEN, 0, WEBROOT);
					}
					break;
				case READ:
				    /* cqe->res is number of bytes that server read */
					if (cqe->res > 0) {
					    printf("read %d bytes\n", cqe->res);
						char *s = "Hello";
					    add_request_write(&ring, request->fd, buf, strlen(s), 0);
						//http_do_request(request, &ring);
					} else {
					    printf("res = %d, close connection.\n", cqe->res);
					    close(request->fd);
					}

					break;
				case WRITE: /* TODO: keep-alive check */
				    /* cqe->res is number of bytes that server wrote */
					if (cqe->res >= 0) {
					    add_request_read(&ring, request->fd, buf, MAX_MESSAGE_LEN, 0, WEBROOT);
					}
					break;
			}
		}
		//printf("%d request completed\n", count);
		io_uring_cq_advance(&ring, count);
	}
    return 0;
}
