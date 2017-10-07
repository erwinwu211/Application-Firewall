#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
#include<string.h>
#include<stdio.h>
#include<getopt.h>
#include<pthread.h>
#include <arpa/inet.h> //for inet_ntoa aton
#include <stdlib.h>

#define REMOTE_SERVER_PORT 80
#define BUF_SIZE 4096
#define QUEUE_SIZE 100
//#define BLOCKED_SERVER "bbs.sjtu.edu.cn"
char BLOCKED_SERVER[128];
char Header[BUFSIZ];
char lastservername[256]="";
char ADMIN_PASSWORD[24];
int lastserverip=0;
char ALLOWED_CLIENTIP[20];//="127.0.0.1";
pthread_mutex_t conp_mutex;
int main(int argc,char **argv);
int checkclient (in_addr_t cli_addr);
void dealonereq(void * arg);
int checkserver(char *hostname);
int gethostname(char *buf,char *hostname,int length);
int connectsever(char *hostname);
int secu_check =0;  //trigger for security check
char *pw; //save password
int connectserver(char* hostname)
{
	int cnt_stat;
	struct hostent *hostinfo;								// info about server
	struct sockaddr_in server_addr; 							// holds IP address
	int remotesocket;


	remotesocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (remotesocket < 0) {
		printf("can't create socket! \n");
		return -1;
	}
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family= AF_INET;
    server_addr.sin_port= htons(REMOTE_SERVER_PORT);

	pthread_mutex_lock(&conp_mutex);

	if (strcmp(lastservername, hostname) != 0)
	{
		hostinfo = gethostbyname(hostname);
		if (!hostinfo) {

			printf("gethostbyname(%s) failed! \n",hostname);
			//pthread_mutex_unlock(&conp_mutex);
			return -1;
		}
		strcpy(lastservername,hostname);
		lastserverip = *(int *)hostinfo->h_addr;
	}
	server_addr.sin_addr.s_addr = lastserverip;
	pthread_mutex_unlock(&conp_mutex);

	//print_serverinfo(server_addr);
    cnt_stat=connect(remotesocket, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if ( cnt_stat< 0) {
		printf("remote connect failed! \n");
		close(remotesocket);
		return -1;
	}
    else
        printf("connected remote server -----> %s:%u.\n",inet_ntoa(*((struct in_addr *)&server_addr.sin_addr.s_addr)),ntohs(server_addr.sin_port));

 	return remotesocket;
}
int checkserver(char *hostname)
{
    FILE *fp1= fopen("1.cof","r");
    char temp[256];
    while (fgets(temp,256,fp1)!=NULL)
    {   strcpy(BLOCKED_SERVER,"");
        if (temp[0]=='B' && temp[1]=='S')
        {   strncpy(BLOCKED_SERVER,temp+3,strlen(temp)-1);
            BLOCKED_SERVER[strlen(BLOCKED_SERVER)-1]='\0';
            if (strstr(hostname, BLOCKED_SERVER) != NULL) //compare
            {
                printf("Destination blocked! \n");
                return -1;
            }
        }
    }
    fclose(fp1);
	return 1;
}

int checkclient (in_addr_t cli_addr)
{   FILE *fp1= fopen("1.cof","r");   //read config file to check allowed clientip everytime
    char temp[256];
    char *clientip=inet_ntoa(*((struct in_addr *)&cli_addr));
    while (fgets(temp,256,fp1)!=NULL)
    {   strcpy(ALLOWED_CLIENTIP,"");
        if (temp[0]=='A' && temp[1]=='C')
        {   strncpy(ALLOWED_CLIENTIP,temp+3,strlen(temp)-1);
            ALLOWED_CLIENTIP[strlen(ALLOWED_CLIENTIP)-1]='\0';
            int a=strcmp(ALLOWED_CLIENTIP,clientip); //compare
            if (a==0){
                fclose(fp1);
                return 1;
            }
        }
    }
    fclose(fp1);
   // inet_aton(ALLOWED_CLIENTIP,allowedip);
    printf("Client IP authentication failed!\n");

    return -1;
}

void dealonereq(void *arg) //sub thread
{
    char buf[BUF_SIZE];
    int bytes;
    char recvbuf[BUF_SIZE];
    char hostname[256];
    int remotesocket;
    int accept_sockfd =(intptr_t)arg;
    pthread_detach(pthread_self());
    bzero(buf,BUF_SIZE);
    bzero(recvbuf,BUF_SIZE);

   if (secu_check==0)           //security check with BASIC AUTHENTICATION
   {    strcat(Header,"HTTP/1.1 401 Unauthorised\n");                       //add 401 error to header
        strcat(Header,"WWW-Authenticate: Basic realm=\"my realm\"\n");      //add www authenticate to header
        send(accept_sockfd,Header,strlen(Header),0);                        //send header
        bytes =read(accept_sockfd,buf,BUF_SIZE);
        //puts(buf);
       // printf("%s",ADMIN_PASSWORD);
        pw=strstr(buf,ADMIN_PASSWORD);   //check ID&password
        if (pw!=NULL) {secu_check=1;}
        close(accept_sockfd);
        return;
   }

    bytes =read(accept_sockfd,buf,BUF_SIZE);
    if (bytes<0)
    {   close(accept_sockfd);
        return;
    }
    gethostname(buf,hostname,bytes);

    if(sizeof(hostname)==0)
    {   printf("Invalid host name");
        close(accept_sockfd);
        return;

    }
    if (checkserver(hostname)==-1)
    {
        close(accept_sockfd);
        return;
    }
    remotesocket =connectserver(hostname);
    if(remotesocket ==-1)
    {   close(accept_sockfd);
        return;
    }
    send(remotesocket,buf,bytes,0);

    while (1)
    {
        int readSizeOnce=0;
        readSizeOnce=read(remotesocket,recvbuf,BUF_SIZE);
        if (readSizeOnce<=0)
            break;
        send(accept_sockfd,recvbuf,readSizeOnce,0);
    }
    close(remotesocket);
	close(accept_sockfd);
}

int gethostname(char* buf,char *hostname, int length)			//tested, must set this pointer[-6] to be '\n' again.
{
	char *p=strstr(buf,"Host: ");
	int i,j = 0;
	bzero(hostname,256);
	if(!p) {p=strstr(buf,"host: ");}
	for(i = (p-buf) + 6, j = 0; i<length; i++, j++)
        {
		if(buf[i] =='\r') {
			hostname[j] ='\0';
			return 0;
		}
		else
			hostname[j] = buf[i];
	}
	return -1;
}



int main(int argc,char **argv)
{   short port=1112;
    FILE *fp1= fopen("1.cof","r");
    char temp[256];
    char opt;
    struct sockaddr_in cl_addr,proxyserver_addr;
    socklen_t sin_size = sizeof(struct sockaddr_in);
    int sockfd, accept_sockfd, on=1;
    pthread_t Clitid;
    while (fgets(temp,256,fp1)!=NULL)
    {   if (temp[0]=='A'&& temp[1]=='P')
        {   strncpy(ADMIN_PASSWORD,temp+3,strlen(temp)-1);
            ADMIN_PASSWORD[strlen(ADMIN_PASSWORD)-1]='\0';
            fclose(fp1);
        }
    }
    while ((opt=getopt(argc,argv,"p:"))!=EOF)
    {   switch(opt)
       {   case 'p':
               port=(short)atoi(optarg);
               break;
           default:
               printf("Usage: %s -p port\n",argv[0]);
               return -1;
       }
    }
    if (port==0)
    {   printf("Invalid port number, try again.\n");
        printf("Usage: %s -p port\n",argv[0]);
        return -1;
    }
    sockfd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(sockfd<0)
    {   printf("Socket failed...Abort...\n");
        return -1;
    }
    memset(&proxyserver_addr,0,sizeof(proxyserver_addr));
    proxyserver_addr.sin_family=AF_INET;
    proxyserver_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    proxyserver_addr.sin_port=htons(port);
    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(char *)&on, sizeof(on));

    if (bind(sockfd,(struct sockaddr *)&proxyserver_addr,sizeof(proxyserver_addr))<0)
    {   printf("Bind failed...Abort...\n");
        return -1;
    }
    if (listen(sockfd,QUEUE_SIZE)<0)
    {   printf("Listen failed...Abort...\n");
        return -1;
    }
    while (1)
    {
        accept_sockfd = accept(sockfd,(struct sockaddr *)&cl_addr,&sin_size);
        if (accept_sockfd<0)
        {   printf("accept failed");
        continue;
        }
        printf("Received a request from %s : %u \n",inet_ntoa(*((struct in_addr *)&cl_addr.sin_addr.s_addr)),ntohs(cl_addr.sin_port));
        if (checkclient(cl_addr.sin_addr.s_addr)==1)
        {
               pthread_create(&Clitid,NULL,(void *)dealonereq,(void *)(intptr_t)accept_sockfd);
        }
        else
           close(accept_sockfd);
    }

    printf("Hello World!\n");
    return 0;
}


