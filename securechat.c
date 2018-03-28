#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define KEYBITS 2048

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int main(int argc, char** argv){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    int encryption = 0;
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char encrypted_key[256];
    //RAND_bytes(key,32);
    strcpy(key,"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    //RAND_pseudo_bytes(iv,16);
    strcpy(iv,"1234567812345678");
    unsigned char data[5000];
    fd_set sockets;
    FD_ZERO(&sockets);
    if(sockfd<0){
        printf("There was an error creating the socket\n");
        return 1;
    }
    struct sockaddr_in serveraddr;
    serveraddr.sin_family=AF_INET;



    serveraddr.sin_port=htons(9989);




    serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");
    int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
    if(e<0){
        printf("There was an error connecting\n");
        return 1;
    }
    
    //Received server public key
    EVP_PKEY *serverkey;
    size_t filesize = recv(sockfd,data,5000,0);
    if(filesize <= 0){
      printf("server key not received program not safe terminating");
    } else {   
    FILE *fp;
    fp = fopen("RSApub.pem","wb"); 
    fwrite(data,1,filesize,fp);
    fclose(fp);
    fp = fopen("RSApub.pem","rb");
    serverkey = PEM_read_PUBKEY(fp,NULL,NULL,NULL);
    fclose(fp);
    }
    int encryptedkey_len = rsa_encrypt(key,32,serverkey,encrypted_key);  
    memset(data,0,5000);

    FD_SET(STDIN_FILENO,&sockets);
    FD_SET(sockfd,&sockets);

    printf("          Welecome to EncryptoChat                         \n");
    printf("             List of Operations                            \n");
    printf("0 - Disconnect from Client Format: 0                       \n");
    printf("1 - Direct Message         Format: 1XMessage X is sender id\n");
    printf("2 - Broadcast Message      Format: 2Message                \n");
    printf("3 - Get Client List        Format: 3                       \n");
    printf("4 - Set Username           Format: 4User#                  \n");
    printf("5 - Kick a User            Format: 5User#                  \n");
    printf("9 - Enable Encryption      Format: 9                       \n");

    while(1){
        fd_set temp_set = sockets;
        select(FD_SETSIZE,&temp_set,NULL,NULL,NULL);
        if(FD_ISSET(STDIN_FILENO,&temp_set)){
            memset(data,0,5000);
            if(read(0,data,5000)!=-1){
                printf("\nSend to server: %s\n", data);
	      send(sockfd,data,5000,0);
                if(strcmp(data,"0\n")==0){
		send(sockfd,data,5000,0);
                    printf("Disconnecting....\n\tExit\n");
                    close(STDIN_FILENO);
                    FD_CLR(STDIN_FILENO,&sockets);
                    exit(0);
                }
                if(strcmp(data,"9\n")==0){
		memset(data,0,5000);
		char type = '9';
		memcpy(data,&type,1);
		memcpy(data+1,&encryptedkey_len,sizeof(int));
		memcpy(data+5,encrypted_key,encryptedkey_len);
                    send(sockfd,data,5000,0);
		encryption = 1;
                } else {
		if(encryption){
	      	char data_temp[5000];
	      	int data_len = encrypt (data,strlen ((char *)data_temp),key,iv,data_temp);
                	memset(data,0,5000);
	      	memcpy(data,iv,16);
		memcpy(data+16,&data_len,sizeof(int));
	      	memcpy(data+20,data_temp,data_len);
		data[20+data_len] = '\0';
		printf("Data_len: %d\n",data_len);
		}
                	send(sockfd,data,5000,0);
		memset(data,0,5000);
	      }
            } else {
                close(STDIN_FILENO);
                FD_CLR(STDIN_FILENO,&sockets);
                continue;
            }
        }else{
            char chatRecv[5000];
            recv(sockfd,chatRecv,5000,0);
            if(strcmp(chatRecv,"KICKED") == 0){
                printf("You've been kicked from the chat server\n");
                exit(0);
            }
            printf("\nReceive from server: %s\n",chatRecv);
            memset(chatRecv,0,5000);
	  
        }

    }
    return 0;
	
}
