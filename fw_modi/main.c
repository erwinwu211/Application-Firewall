//progammed by Wu Erwin from Shanghai Jiaotong University, School of Information Security. Student ID: 5130369026

#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#define CONFIG_FILE "/home/wt/Codeblocks/develop1/Appfw/1.cof"
char barcase[1000];
char accnt[40];
char pswd[40];
char IP[20];
char blck[256];
char base64_map[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char base64_decode_map[256] = {
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255,
     255, 0, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28,
     29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
     49, 50, 51, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};

void base64_encode(char *src, int src_len, char *dst)
{
        int i = 0, j = 0;

        for (; i < src_len - src_len % 3; i += 3) {
                dst[j++] = base64_map[(src[i] >> 2) & 0x3f];
                dst[j++] = base64_map[((src[i] << 4) | (src[i + 1] >> 4)) & 0x3f];
                dst[j++] = base64_map[((src[i + 1] << 2) | (src[i + 2] >> 6 )) & 0x3f];
                dst[j++] = base64_map[src[i + 2] & 0x3f];
        }

        if (src_len % 3 == 1) {
                 dst[j++] = base64_map[(src[i] >> 2) & 0x3f];
                 dst[j++] = base64_map[(src[i] << 4) & 0x3f];
                 dst[j++] = '=';
                 dst[j++] = '=';
        }
        else if (src_len % 3 == 2) {
                dst[j++] = base64_map[(src[i] >> 2) & 0x3f];
                dst[j++] = base64_map[((src[i] << 4) | (src[i + 1] >> 4)) & 0x3f];
                dst[j++] = base64_map[(src[i + 1] << 2) & 0x3f];
                dst[j++] = '=';
        }

        dst[j] = '\0';
}

void base64_decode(char *src, int src_len, char *dst)
{
        int i = 0, j = 0;

        for (; i < src_len; i += 4) {
                dst[j++] = base64_decode_map[src[i]] << 2 |
                        base64_decode_map[src[i + 1]] >> 4;
                dst[j++] = base64_decode_map[src[i + 1]] << 4 |
                        base64_decode_map[src[i + 2]] >> 2;
                dst[j++] = base64_decode_map[src[i + 2]] << 6 |
                        base64_decode_map[src[i + 3]];
        }

        dst[j] = '\0';
}

void print_delete() //print out delete list
{   FILE *fp1= fopen(CONFIG_FILE,"r");
    char temp[256];
    int i=1;
    while (fgets(temp,256,fp1)!=NULL)
    {
        if(temp[0]=='A'&& temp[1]=='C')
        {   printf("%d. Allowed Client IP : ",i);
            printf("%s",temp+3);
            i=i+1;
        }
        if(temp[0]=='B'&& temp[1]=='S')
        {   printf("%d. Blocked Server : ",i);
            printf("%s",temp+3);
            i=i+1;
        }
    }
    fclose(fp1);
    printf("plz enter the number you wanna delete:\n");
}

void print_file()
{   FILE *fp1= fopen(CONFIG_FILE,"r");
    char temp[256];
    while (fgets(temp,256,fp1)!=NULL)
    {   if(temp[0]=='A'&& temp[1]=='P')
        {   printf("user ID and password : ");
            base64_decode(temp+3, strlen(temp)-3, temp);
            printf("%s\n",temp);
        }
        if(temp[0]=='A'&& temp[1]=='C')
        {   printf("Allowed Client IP : ");
            printf("%s",temp+3);
        }
        if(temp[0]=='B'&& temp[1]=='S')
        {   printf("Blocked Server : ");
            printf("%s",temp+3);
        }
    }
    fclose(fp1);
}

void write_file(char a)
{   FILE *fp2= fopen("2.txt","w");
    FILE *fp1= fopen(CONFIG_FILE,"r");
    char temp[256];
    while (fgets(temp,256,fp1)!=NULL)
    {   if(a== 'a' && temp[0]=='A'&& temp[1]=='P')
        {   fputs(accnt,fp2);
            fprintf(fp2,"\n");
            fgets(temp,256,fp1);
            a=0;
        }
        if(a=='b' && temp[0]=='B'&& temp[1]=='S')
        {   fputs(blck,fp2);
            fprintf(fp2,"\n");
            a=0;
        }
        if(a== 'c' && temp[0]=='A'&& temp[1]=='C')
        {   fputs(IP,fp2);
            fprintf(fp2,"\n");
            a=0;
        }
        fputs(temp,fp2);

    }
    printf("Successfully modified!\n");
    fclose(fp2);
    fclose(fp1);
    remove(CONFIG_FILE);
    rename("2.txt",CONFIG_FILE);
}

void delete_line(int a)
{   FILE *fp2= fopen("2.txt","w");
    FILE *fp1= fopen(CONFIG_FILE,"r");
    char temp[256];
    int i=1;
    while (fgets(temp,256,fp1)!=NULL)
    {   if(temp[0]=='A'&& temp[1]=='P')
        {    fputs(temp,fp2);
        }
        if(temp[0]=='B'&& temp[1]=='S')
        {   if(i!=a){fputs(temp,fp2);}
            i=i+1;
        }
        if(temp[0]=='A'&& temp[1]=='C')
        {   if(i!=a){fputs(temp,fp2);}
            i=i+1;
        }
    }
    if (i<=a){printf("Invalid input, plz try again.\n");}
    else{ printf("Successfully deleted!\n");}
    fclose(fp2);
    fclose(fp1);
    remove(CONFIG_FILE);
    rename("2.txt",CONFIG_FILE);
}

int main()
{   char temp[256];
    int i;
    printf("Welcome to Application Firewall modification system! Enter -h for more help.\n");
    while (1)
    {   strcpy(temp,"");
        scanf("%s",barcase);
        if (barcase[0]!='-'){barcase[1]='z';} //judge '-'
        switch(barcase[1])
        {   case 'a':               //change pw
                printf("plz enter a new account(less than 8 char): \n");
                scanf("%s",accnt);
                printf("plz enter a new password(less than 8 char): \n");
                scanf("%s",pswd);
                strcat(accnt,":");
                strcat(accnt,pswd);
                base64_encode(accnt,strlen(accnt),pswd);
                strcpy(accnt,"AP ");
                strcat(accnt,pswd);
                write_file('a');
                break;
            case 'c':           //add allowed ip
                printf("plz enter a new allowed IP (XXX.XXX.XXX.XXX): \n");
                scanf("%s",IP);
                strcpy(temp,"AC ");
                strcat(temp,IP);
                strcpy(IP,temp);
                write_file('c');
                break;
            case 'b':           // add block server
                printf("plz enter a new blocked server : \n");
                scanf("%s",blck);
                strcpy(temp,"BS ");
                strcat(temp,blck);
                strcpy(blck,temp);
                write_file('b');
                break;
            case 'd':       //delete rules
                print_delete();
                scanf("%d",&i);
                delete_line(i);
                break;
            case 'h': //help file
                printf("Plz enter the following command:\n-p To print the config\n");
                printf("-a To change the userID and password\n-b To add blocked server\n");
                printf("-c To add allowed client IP\n-d To delete existing rules\n");
                printf("-q To exit this program. \n");
                break;
            case 'p':       //print config
                print_file();
                break;
            case 'q':       //quit
                return 0;
            default:
                printf("Invalid command!\n");
        }
    }

    return 0;
}
