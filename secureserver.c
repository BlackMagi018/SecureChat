#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

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

int main(void) {
    //Crypto Setup
    unsigned char *pubfilename = "RSApub.pem";
    unsigned char *privfilename = "RSApriv.pem";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char *plaintext = (unsigned char *)"This is a test string to encrypt.";
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    int decryptedtext_len, ciphertext_len;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    EVP_PKEY *pubkey, *privkey;
    FILE* pubf = fopen(pubfilename,"rb");
    pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
    fseek(pubf,0,SEEK_SET);
    char public[1000];
    size_t size = fread(public,1,5000,pubf);
    unsigned char encrypted_key[256];
    FILE* privf = fopen(privfilename,"rb");
    privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
    unsigned char decrypted_key[32];
    strcpy(key,"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    strcpy(iv,"1234567812345678");

    //Admin Setup
    int num_clients = 0;
    fd_set sockets;
    FD_ZERO (&sockets);
    char * data = (char *)malloc(5000 * sizeof(char));
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Create Client List
    char **clients = malloc(FD_SETSIZE * sizeof(char *));
    for (int temp = 0; temp < FD_SETSIZE; temp++) {
        clients[temp] = (char *) malloc(sizeof(char) * 25);
        sprintf(clients[temp],"User #%d\n",temp);
    }

    //Create Client Encryption Key List
    unsigned char **keys = malloc(FD_SETSIZE * sizeof(unsigned char *));
    for (int temp = 0; temp < FD_SETSIZE; temp++) {
        keys[temp] = (unsigned char *) malloc(sizeof(unsigned char) * 256);
        sprintf(keys[temp],"%s","0");
    }

    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;


    serveraddr.sin_port = htons(9989);


    serveraddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
    listen(sockfd, 10);
    FD_SET (sockfd, &sockets);

    while (1) {
        socklen_t len = sizeof(clientaddr);
        fd_set tmp_set = sockets;
        select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        int i;
        for (i = 0; i < FD_SETSIZE; ++i) {
            if (FD_ISSET (i, &tmp_set)) {
                if (i == sockfd) {
                    int clientsocket = accept(sockfd, (struct sockaddr *) &clientaddr, &len);
                    FD_SET (clientsocket, &sockets);
                    num_clients++;
                    printf("Client #%d connected\n", clientsocket);
	          send(clientsocket,public,(int) size,0);
	          printf("Public Key sent to client\n");
	 } else {
                    memset(data,0,5000);
                    size_t size = recv(i, data, 5000, 0);	
		if(strcmp(keys[i],"0") != 0){
			char data_temp [5000];
			unsigned char siv[16];
			memcpy(siv,data,16);
			printf("IV: %s\n",siv);
			int data_len;
			memcpy(&data_len,data+16,4);
			printf("Data_len: %d\n",data_len);
			decryptedtext_len = decrypt(data+20,data_len,keys[i],iv,data_temp);	
			printf("Decrypted Text Length: %d\n",decryptedtext_len);
			memcpy(data,data_temp,decryptedtext_len);
		}
		printf("Got from client: %s\n", data);
                    char c = data[0];
                    int control = (int) strtol(&c, NULL, 10);
                    switch (control) {
                        case 0:
                            //close client
                            printf("Disconnecting from Client %d\n", i);
                            fflush(stdout);
                            close(i);
                            FD_CLR(i, &sockets);
                            num_clients--;
		        keys[i] = "0";
                            break;
                        case 1:
                            //direct message
                            printf("%s", data);
                            char r[2];
                            strncpy(r,data+1,1);
                            printf("r: %s\n", r);
                            int recipient = (int) strtol(r, NULL, 10);
                            printf("recipient: %d\n", recipient);
                            printf("Sending a DM from %d to %d. Message: %s\n", i, recipient, data + 2);
                            if (FD_ISSET(recipient, &sockets)) {
                                send(recipient, data + 2, strlen(data + 2) + 1, 0);
                            }
                            break;
                        case 2:
                            //broadcast message
                            printf("Broadcast Message: %s", data + 1);
                            for (int loop = 0; loop < FD_SETSIZE; loop++) {
                                if(FD_ISSET(loop,&sockets)){
                                    if(loop != sockfd){
                                        send(loop, data + 1, strlen(data) + 1, 0);
                                    }
                                }
                            }
                            break;
                        case 3:
                            //client list
                            printf("Send Client List\n");
                            memset(data,0,5000);
                            strcat(data,"\nUser List\n");
                            for (int loop = 0; loop < FD_SETSIZE; loop++) {
                                if(FD_ISSET(loop,&sockets)){
                                    if(loop != sockfd){
                                        strcat(data,clients[loop]);
                                    }
                                }
                            }
                            send(i, data, strlen(data) + 1, 0);
                            //fflush(stdout);
                            break;
                        case 4:
                            //set username
                            strncpy(clients[i],data+1,25);
                            char reply [50];
                            sprintf(reply,"Username set to %s",clients[i]);
                            send(i, reply,51,0);
                            //fflush(stdout);
                            break;
                        case 5:
                            //kick user
                            printf("Attempt to Kick a User\n");
                            char p = data[1];
                            int user = (int) strtol(&p, NULL, 10);
                            memset(data,0,5000);
                            strcat(data,"Confirm Kicking with 6User#");
                            send(i, data, strlen(data) + 1, 0);
                            break;
                        case 6:
                            //confirm kick user
                            printf("Kicking User\n");
                            char q = data[1];
                            int bye = (int) strtol(&q, NULL, 10);
                            memset(data,0,5000);
                            strcat(data,"KICKED");
                            send(bye, data, strlen(data) + 1, 0);
                            close(bye);
                            FD_CLR(user,&sockets);
                            break;
	         	     case 9:
			//enable encryption with client
			printf("Encrypting Client %d's messages from now on\n",i);
			int encryptedkey_len;
			printf("Here 3\n");
			memcpy(&encryptedkey_len,data+1,sizeof(int));
			memcpy(encrypted_key,data+5,encryptedkey_len);
			printf("Here 4\n");
			int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, privkey, decrypted_key);
			memcpy(keys[i],decrypted_key,decryptedkey_len);
			printf("Client Encryption Key saved\n");
			printf("Performing test enc/dec");
			char test1 [5];
			strcpy(test1,"2Hello");
			printf("Here 1\n");
			fflush(stdout);
			int ciphertext_len = encrypt (test1, strlen ((char *)test1),key,iv,ciphertext);
			printf("Here 2\n");
			fflush(stdout);
			memset(decryptedtext, 0,1024);
			int decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key,iv,decryptedtext);
			decryptedtext[decryptedtext_len] = '\0';
			printf("%s\n",decryptedtext);
			memset(data,0,5000);
			break;
                        default:
                            break;
                    }
                }
            }
        }
    }
}
