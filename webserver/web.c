#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

char response[] = "HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF8\r\n\r\n"
"<!DOCTYPE html><html><head><title>hw1</title></head>\r\n"
"<body><h1>hello, world</h1>\r\n"
"<form action=\"\" method=\"post\" enctype=\"multipart/form-data\">\r\n"
"<input type=\"file\" name=\"file\">\r\n"
"<br />\r\n"
"<input type=\"submit\" value=\"upload\"></form>\r\n"
"<img src=\"test.jpg\"></body></html>\r\n";

int main()	{

	pid_t pid;
	int sock, cli;
	int on = 1;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	int imgfd;
	int filefd;
	char *filename;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock < 0)	{

		perror("socket");
		exit(1);
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(8080);

	if(bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)	{

		perror("bind");
		close(sock);
		exit(1);
	}

	if(listen(sock, 10) == -1)	{

		perror("listen");
		close(sock);
		exit(1);
	}

	socklen_t cli_len = sizeof(client_addr);

	char buf[1024];
	char tmp[1024];
	int i, n;

	while(1)	{

		cli = accept(sock, (struct sockaddr*)&client_addr, &cli_len);

		if(cli == -1)	{

			perror("Can't accept");
			continue;
		}

		printf("Got connection\n\n");

		if(fork() == 0)	{

			close(sock);

			memset(buf, 0, 1024);

			read(cli, buf, 1023);
			printf("%s", buf);

			if(strncmp(buf, "GET /test.jpg", 13)  == 0)	{

				imgfd = open("test.jpg", O_RDONLY);
				sendfile(cli, imgfd, NULL, 47000);
				close(imgfd);
			}

//			if(strncmp(buf, "POST /", 6) == 0)	{

//				strcpy(tmp, buf);

			//	char *cur = strstr(tmp, "filename");
			//	cur += 10;

//				char *end = cur;
//				end = strstr(cur, "\"");
//				end = '\0';

//				strcpy(filename, cur);

//				filefd = open(filename, O_RDONLY);

//				system("");
//				close(filefd);
//				memset(tmp, '\0', sizeof(tmp));
		//	}

			else
				write(cli, response, sizeof(response)-1);

			close(cli);
			printf("closing\n");
			printf("----------------------------------\n");
			exit(0);
		}

		close(cli);

	}

	return 0;
}
