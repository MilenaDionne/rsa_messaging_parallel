/****************** ./server port# ****************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> // for the structures
#include <errno.h> // for perror
#include <fcntl.h> // for open
#include <unistd.h> // for close
// for inet_ntohs
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rsa.h"
#include <iostream> 
#include <fstream>
#include <string>
#include <chrono>
#include <cstdlib>
#include "ipp.h"
#include "tbb/tbb.h"


#define ERROR 			-1
#define MAX_CLIENTS 	5
#define MAX_DATA		1024
#define BUFFER_DECRYPT 	100000

struct client_info {
	int sockno;
	char ip[INET_ADDRSTRLEN];
};


int main(int argc, char **argv)
{
  struct public_key_class pub[1];
  struct private_key_class priv[1];

  PRIME_SOURCE_FILE= (char *)"primes.txt";
  int primes[1];
  rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);


  int j;
	char temp;

	 printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
 
  struct sockaddr_in server;
	struct sockaddr_in client;
	int server_socket;
	int client_socket;
	int sockaddr_len = sizeof(struct sockaddr_in);
	int data_len;
	
  char encrypt[BUFFER_DECRYPT];
  char data[MAX_DATA];
	char ip[INET_ADDRSTRLEN];
  char decrypt[MAX_DATA];

	if (argc < 2) {
         printf("ERROR, no port provided\n");
         exit(-1);
     }
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
	{
		perror("socket: ");
		exit(-1);
	}
  

	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(argv[1]));
	server.sin_addr.s_addr = INADDR_ANY; //all avail interf on machine
	bzero(&server.sin_zero, 8);
	

  if(bind(server_socket,(struct sockaddr *)&server, sockaddr_len) == ERROR) {
		perror("bind: ");
		exit(-1);
	}

	if(listen(server_socket, MAX_CLIENTS) == ERROR) {
		perror("listen");
		exit(-1);
	}

  while(1) {
		if((client_socket = accept(server_socket,(struct sockaddr *)&client,(socklen_t*)&sockaddr_len)) == ERROR) {
			perror("accept");
			exit(-1);
		}
		
		
		printf("%s connected\n",ip);
		printf("New Client connected from port# %d and IP %s\n", ntohs(client.sin_port), inet_ntoa(client.sin_addr));
		data_len = 1;
  
		while(data_len)
		{
			data_len = recv(client_socket, data, MAX_DATA, 0);
			
			if(data_len)
			{
				
				data[data_len-1] = '\0';
				printf("Original: %s\n", data);
				for(int i=0; i < strlen(data); i++){
					printf("%lld\n", (long long)data[i]);
				} 
        long long *encrypted = rsa_encrypt(data, sizeof(data), pub);

        if (!encrypted){
          fprintf(stderr, "Error in encryption!\n");
          return 1;
        }

        int encrypt_size;
        std::string encrypts; 
        printf("Encrypted:\n");
        for(int i=0; i < strlen(data); i++){
          printf("%lld\n", (long long)encrypted[i]);
          std::string temp = std::to_string(encrypted[i]);
          encrypts += temp;
          
          for (int i = 0; i < temp.length(); i++){
            encrypt[i+encrypt_size] = temp[i];
            
          }
          encrypt_size += temp.length();
        } 
       
        
        send(client_socket, encrypt, encrypt_size, 0);

        
        long long p = 0; //find p
  			long long q = 0; //find q
        int count = 8; 

        std::ifstream fichier; 
    		fichier.open(PRIME_SOURCE_FILE); 
				std::ifstream fichier2; 

				if (!fichier) {// If the file is not found...
					std::cout << "Le fichier " << PRIME_SOURCE_FILE << "n'existe pas" << std::endl;
					exit(0);
				}
				
				auto start = std::chrono::steady_clock::now();
        int countprimes = 0, prime;
        int *buffer = (int*) ippMalloc(78500*sizeof(int));
        

        
        
        while ( fichier >> prime){ 
            buffer[countprimes] = prime; 
            countprimes++; 
            
        }
        
        fichier.close();

      

				int i = 0; 

      
        tbb::parallel_for(tbb::blocked_range2d<int>(0, countprimes, 0, countprimes),
        [&](const tbb::blocked_range2d<int>& r) {
           
            for (int j = r.rows().begin(), j_end = r.rows().end(); j < j_end; j++) {
                for (int k = r.cols().begin(), k_end = r.cols().end(); k < k_end; k++) {
                    if (buffer[k] * buffer[j] != (int)pub->modulus) {

                    }
                    else {
                        p = buffer[k];
                        q = buffer[j];

                        std::cout << "q = " << q << " and p = " << p << std::endl;
                        
                        if (tbb::task::self().cancel_group_execution())
                            
                        return;
                    }
                    
                }
            }
            
        });

        ippFree(buffer);
      
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start); 
        std::cout << "finding p and q elapsed time: " << duration.count()<< " ms\n";

        struct private_key_class to_find_priv[1];
        long long phi_max = (p-1)*(q-1);

        to_find_priv->modulus = pub->modulus;

        long long d = ExtEuclid(phi_max,pub->exponent);

				while(d < 0){
					d = d+phi_max;
				}
				to_find_priv->exponent = d;
  
        char *decrypted = rsa_decrypt(encrypted, 8*sizeof(data), to_find_priv, count);
        if (!decrypted){
          fprintf(stderr, "Error in decryption!\n");
          return 1;
        }

        int decrypt_size;
        std::string decrypts; 
        printf("Decrypted:\n");
        for(int i=0; i < strlen(data); i++){
          printf("%lld\n", (long long)decrypted[i]);
          std::string temp = std::to_string(decrypted[i]);
          decrypts += temp;

          for (int i = 0; i < temp.length(); i++){
            decrypt[i+decrypt_size] = temp[i];
            
          }
          decrypt_size += temp.length();
        } 
      
        
        send(client_socket, decrypt, decrypt_size, 0);


        printf("\n");
        free(encrypted);
        free(decrypted);
        printf("\n");
      }
    } 
				

  }

  

  return 0;
}
