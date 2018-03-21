#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
int main(void) {
    int num_clients = 0;
    fd_set sockets;
    FD_ZERO (&sockets);
    char * data = (char *)malloc(5000 * sizeof(char));
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Create Client
    char **clients = malloc(FD_SETSIZE * sizeof(char *));
    for (int temp = 0; temp < FD_SETSIZE; temp++) {
        clients[temp] = (char *) malloc(sizeof(char) * 25);
        sprintf(clients[temp],"User #%d\n",temp);
    }

    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(9949);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
    listen(sockfd, 10);
    FD_SET (sockfd, &sockets);

    while (1) {
        socklen_t len = sizeof(clientaddr);
        fd_set tmp_set = sockets;
        int fd_num = select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        int i;
        for (i = 0; i < FD_SETSIZE; ++i) {
            if (FD_ISSET (i, &tmp_set)) {
                if (i == sockfd) {
                    int clientsocket = accept(sockfd, (struct sockaddr *) &clientaddr, &len);
                    FD_SET (clientsocket, &sockets);
                    num_clients++;
                    printf("Client #%d connected\n", clientsocket);
                } else {
                    memset(data,0,5000);
                    recv(i, data, 5000, 0);
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
                        default:
                            break;
                    }
                }
            }
        }
    }
}

#pragma clang diagnostic pop