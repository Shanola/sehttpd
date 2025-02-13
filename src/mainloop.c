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

#define LISTENQ 4096

#define MAX_MESSAGE_LEN 2048
#define IOURING_QUEUE_DEPTH 4096


enum {
    ACCEPT,
	READ,
	WRITE,
	PROV_BUF,
};

char buffers[LISTENQ][MAX_MESSAGE_LEN] = {};

void add_request_accept(struct io_uring *ring, int sockfd, struct sockaddr_in *client_addr, socklen_t *client_len, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	http_request_t *req = malloc(sizeof(http_request_t) + sizeof(struct iovec));
	req->fd = sockfd;
	req->event_type = ACCEPT;
	io_uring_prep_accept(sqe, sockfd, (struct sockaddr *)client_addr, client_len, 0);
	io_uring_sqe_set_data(sqe, req);

    io_uring_submit(ring);
}

void add_request_read(struct io_uring *ring, int fd, unsigned msg_size, unsigned flags, char *root, int gid)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	sqe->buf_group = gid;
	http_request_t *req = malloc(sizeof(http_request_t) + sizeof(struct iovec));
	init_http_request(req, fd, root);
	req->event_type = READ;
	io_uring_prep_recv(sqe, fd, NULL, msg_size, 0);
	io_uring_sqe_set_flags(sqe, flags);
	io_uring_sqe_set_data(sqe, req);

	io_uring_submit(ring);
}

void add_request_write(struct io_uring *ring, int fd, int bid, void *msg, unsigned msg_size, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	
	http_request_t *req = malloc(sizeof(http_request_t) + sizeof(struct iovec));
	req->fd = fd;
	req->event_type = WRITE;
	req->bid = bid;
	io_uring_prep_send(sqe, fd, /*&buffers[bid]*/msg, msg_size, 0);
	io_uring_sqe_set_data(sqe, req);
	
	io_uring_submit(ring);
}

void add_request_provide_buffers(struct io_uring *ring, unsigned msg_size, int buf_cnt, int gid, int bid)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	
	http_request_t *req = malloc(sizeof(http_request_t) + sizeof(struct iovec));
	req->fd = 0;
	req->event_type = PROV_BUF;
	io_uring_prep_provide_buffers(sqe, buffers[bid], msg_size, buf_cnt, gid, bid);
	io_uring_sqe_set_data(sqe, req);

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

/* TODO: use command line options to specify */
#define PORT 8085
#define WEBROOT "./www"

int main()
{
    int group_id = 0;
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

	if (io_uring_queue_init(IOURING_QUEUE_DEPTH, &ring, 0) != 0) {
	    printf("io_uring init failed.\n");
		return EXIT_FAILURE;
	}
	
	printf("Server started.\n");
	
	struct io_uring_cqe *cqe;
    add_request_provide_buffers(&ring, MAX_MESSAGE_LEN, LISTENQ, group_id, 0);
    io_uring_wait_cqe(&ring, &cqe);
	if(cqe->res < 0) {
	    printf("Error: provide buffer, cqe->res = %d\n", cqe->res);
		return EXIT_FAILURE;
	}
	io_uring_cqe_seen(&ring, cqe);
	
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	add_request_accept(&ring, listenfd, &client_addr, &client_len, 0);

	while (1) {
	    //io_uring_submit_and_wait(&ring, 1);
        //struct io_uring_cqe *cqe;
		//unsigned head;
		//unsigned count = 0;
		//io_uring_for_each_cqe(&ring, head, cqe) {
		//    count++;	
		int ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
		    printf("error when wait cqe\n");
			return EXIT_FAILURE;
		}
		http_request_t *request = io_uring_cqe_get_data(cqe);
		if (cqe->res == -ENOBUFS) {
		    printf("Error: no buffer space available\n");
			return EXIT_FAILURE;
		}
	    printf("fd: %d / ", request->fd);
		if (request->event_type == 0) {
		    printf("0 accepted, clientfd = %d", cqe->res);
		} else if (request->event_type == 1) {
		    printf("1 read");
		} else if (request->event_type == 2) {
		    printf("2 wrote");
		} else if (request->event_type == 3) {
		    printf("3 provided");
		}
		printf("\n");
	    switch (request->event_type) {
		    case ACCEPT:
		        add_request_accept(&ring, listenfd, &client_addr, &client_len, 0);
			    /* cqe->res might be client fd */
			    if (cqe->res >= 0) { /* TODO: check contain "=" or not */
				    add_request_read(&ring, cqe->res, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT, WEBROOT, group_id);
			    }
			    break;
		    case READ:
			    /* cqe->res is number of bytes that server read */
			    if (cqe->res > 0) {
				    int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
					printf("---\n\n%s---\n", buffers[bid]);
				    http_do_request(cqe->res, request, bid, buffers[bid], &ring, MAX_MESSAGE_LEN, group_id);
					//add_request_write(&ring, request->fd, bid, cqe->res, 0);
			    } else {
				    printf("errno = %d, close fd=%d.\n", cqe->res, request->fd);
				    shutdown(request->fd, SHUT_RDWR);
					//close(request->fd);
			    }
			    break;
		    case WRITE: /* TODO: keep-alive check */
			    /* cqe->res is number of bytes that server wrote */
			    if (cqe->res > 0) {
				    add_request_provide_buffers(&ring, MAX_MESSAGE_LEN, 1, group_id, request->bid);
				    add_request_read(&ring, request->fd, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT, WEBROOT, group_id);
			    } else {
				    printf("Hey!!! Got you\n"); //TODO
				}
			    break;
		    case PROV_BUF:
		        if (cqe->res < 0) {
				    printf("Error: provide buffers");
				    return EXIT_FAILURE;
			    }
			    break;
	    }
		//}
		//io_uring_cq_advance(&ring, count);
		io_uring_cqe_seen(&ring, cqe);
	}
    return 0;
}
