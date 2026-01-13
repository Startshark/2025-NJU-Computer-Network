#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define HTTPS_PORT 443
#define HTTP_PORT 80

void handle_http_request(int client_sock)
{
	// 只做301重定向
	char redirect_response[1024];
	char buf[1024] = {0};
	read(client_sock, buf, sizeof(buf));
	
	char path[256] = "/";
	char host[256] = "localhost";
	sscanf(buf, "GET %s", path);
	
	// 提取Host头
	char *host_start = strstr(buf, "Host: ");
	if (host_start) {
		sscanf(host_start + 6, "%s", host);
	}
	
	snprintf(redirect_response, sizeof(redirect_response), 
		"HTTP/1.1 301 Moved Permanently\r\n"
		"Location: https://%s%s\r\n"
		"Content-Length: 0\r\n"
		"\r\n", host, path);
	
	write(client_sock, redirect_response, strlen(redirect_response));
	close(client_sock);
}

void handle_https_request(SSL* ssl)
{
	if (SSL_accept(ssl) == -1) {
		perror("SSL_accept failed");
		exit(1);
	}

	char buf[4096] = {0};
	int bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes < 0) {
		perror("SSL_read failed");
		exit(1);
	}

	char path[256] = ".";
	long start = 0, end = -1;
	sscanf(buf, "GET %s", path + 1);
	
	// 处理默认文件
	if (strcmp(path, "./") == 0) {
		strcpy(path, "./index.html");
	}
	
	char *range_start = strstr(buf, "Range: bytes=");
	if (range_start) {
		sscanf(range_start + 13, "%ld-%ld", &start, &end);
	}

	FILE *file = fopen(path, "rb");
	if (!file) {
		const char* response = "HTTP/1.1 404 Not Found\r\n\r\nFile not found";
		SSL_write(ssl, response, strlen(response));
	} else {
		fseek(file, 0, SEEK_END);
		long file_size = ftell(file);
		fseek(file, 0, SEEK_SET);

		char *content = malloc(file_size);
		fread(content, 1, file_size, file);
		fclose(file);

		char response[512];
		
		if (range_start) {
			if (end == -1) end = file_size - 1;
			
			snprintf(response, sizeof(response), 
				"HTTP/1.1 206 Partial Content\r\n"
				"Content-Length: %ld\r\n"
				"Content-Range: bytes %ld-%ld/%ld\r\n\r\n", 
				end - start + 1, start, end, file_size);
			SSL_write(ssl, response, strlen(response));
			SSL_write(ssl, content + start, end - start + 1);
		} else {
			snprintf(response, sizeof(response),
				"HTTP/1.1 200 OK\r\n"
				"Content-Length: %ld\r\n\r\n",
				file_size);
			SSL_write(ssl, response, strlen(response));
			SSL_write(ssl, content, file_size);
		}
		free(content);
	}

	int sock = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sock);
}

struct thread_args {
	SSL_CTX *ctx;
	int port;
};

void *setup(void *arg) {
	struct thread_args *args = (struct thread_args *)arg;
	SSL_CTX *ctx = args->ctx;
	int port = args->port;
	// init socket, listening to specified port
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		if (port == HTTP_PORT) {
			handle_http_request(csock);
		}
		else {
			SSL *ssl = SSL_new(ctx); 
			SSL_set_fd(ssl, csock);
			handle_https_request(ssl);
		}
	}

	close(sock);
	SSL_CTX_free(ctx);
}

int main()
{
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}

	pthread_t tid[2];
	struct thread_args https_args = {ctx, HTTPS_PORT};
	struct thread_args http_args = {ctx, HTTP_PORT};
	pthread_create(&tid[0], NULL, setup, &https_args);
	pthread_create(&tid[1], NULL, setup, &http_args);


	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);

	return 0;
}
