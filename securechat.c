#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char** argv){
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    char data[5000];
    fd_set sockets;
    FD_ZERO(&sockets);
    if(sockfd<0){
        printf("There was an error creating the socket\n");
        return 1;
    }
    struct sockaddr_in serveraddr;
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(9949);
    serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");
    int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));

    if(e<0){
        printf("There was an error connecting\n");
        return 1;
    }

    FD_SET(STDIN_FILENO,&sockets);
    FD_SET(sockfd,&sockets);

    printf("          Welecome to EncryptoChat                         \n");
    printf("             List of Operations                            \n");
    printf("0 - Disconnect from Client Format: 0                       \n");
    printf("1 - Direct Message         Format: 1XMessage X is sender id\n");
    printf("2 - Broadcast Message      Format: 2Message                \n");
    printf("3 - Get Client List        Format: 3                       \n");
    printf("4 - Set Username           Format: 4User#                  \n");
	printf("5 - Kick a User            Format: 5User#                      \n\n");

    while(1){
        fd_set temp_set = sockets;
        select(FD_SETSIZE,&temp_set,NULL,NULL,NULL);
        if(FD_ISSET(STDIN_FILENO,&temp_set)){
            memset(data,0,5000);
            if(read(0,data,5000)!=-1){
                printf("\nSend to server: %s\n", data);
                data[strlen(data)+1] = (char) "\0";
                send(sockfd,data,strlen(data)+1,0);
                if(strcmp(data,"0\n")==0){
                    printf("Disconnecting....\n\tExit\n");
                    close(STDIN_FILENO);
                    FD_CLR(STDIN_FILENO,&sockets);
                    exit(0);
                }
            }else{
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
