/****************** ./client ip port# ****************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> // for the structuinput
#include <errno.h> // for perror
#include <fcntl.h> // for open
#include <unistd.h> // for close
// for inet_ntohs
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rsa.h"
#include <iostream>



#define ERROR 			-1
#define BUFFER			1024
#define BUFFER_DECRYPT 	100000

int main(int argc, char **argv)
{
	struct sockaddr_in remote_server;
	struct sockaddr_in sa;
	int client_socket;
	char output[BUFFER];
	char username[100];
	char input[BUFFER];
	char ip[INET_ADDRSTRLEN];
	int len;
	int len1;
	char encrypt[BUFFER_DECRYPT];

	if (argc < 3) {
         printf("ERROR, no ip and port provided\n");
         exit(-1);
     }

	 if((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
	{
		perror("socket: ");
		exit(-1);
	}
  
	
	strcpy(username,argv[1]);
	remote_server.sin_family = AF_INET;
	remote_server.sin_port = htons(atoi(argv[2]));
	remote_server.sin_addr.s_addr = inet_addr("127.0.0.1");
	bzero(&remote_server.sin_zero, 8);

	if(connect(client_socket,(struct sockaddr *)&remote_server, sizeof(struct sockaddr_in)) == ERROR) {
		perror("connect");
		exit(-1);
	}
	// store this IP address in sa:
	inet_pton(AF_INET, "127.0.0.1", &(sa.sin_addr));

	// now get it back and print it
	inet_ntop(AF_INET, &(sa.sin_addr), ip, INET_ADDRSTRLEN);

	//inet_ntop(AF_INET, (struct sockaddr *)&remote_server, ip, INET_ADDRSTRLEN);
	printf("connected to %s, start chatting\n",ip);
	
	while(1) {
		fgets(input, BUFFER, stdin);
		send(client_socket, input, strlen(input), 0);
		
		
		
		len1 = recv(client_socket, encrypt, BUFFER_DECRYPT, 0);
		len = recv(client_socket, output, BUFFER, 0);
		printf("Encrypted message is: %s\n", encrypt);
		printf("Decrypted message in char is : %s\n\n", output);
		
		if(len < 0) {
			perror("message not sent");
			exit(1);
		}

		memset(output,'\0', sizeof(output)); //memset() is used to fill a block of memory with a particular value.
		memset(input,'\0', sizeof(input));
		
		

        
	}

	close(client_socket);

}
