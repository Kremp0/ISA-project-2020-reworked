/*
 * Samuel Krempaský, xkremp01
 * 
 * xkremp01
 * used for SSL headers https://tls13.ulfheim.net/
 * some code was inspired by prof. Petr Matousek, 2020
 * especially included libraries and main loop in main
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip6.h>
#include <err.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

#define SYN     0b10000
#define FIN     0b01000
#define RST     0b00100
#define PUSH    0b00010
#define ACK     0b00001

#define HOSTLENGHT 253          //https://en.wikipedia.org/wiki/Hostname


/*
IN: 
sslsniff [-r <file>] [-i interface]
*/

/*
OUT:
<timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>
*/

typedef enum {
    START,
    CLIENT_SYN,
    SERVER_SYN_ACK,
    CLIENT_ACK,
    CLIENT_ACK_HELLO,
    SERVER_HELLO,
    CONNECTION_EST,//connection established
    FIN_FIRST,
    FIN_SECOND,
    CLOSED,
    END

}ConnectionSM;

//just a switch for printing out
bool isFile=true;

typedef  struct owntime {
    int sec; 
    // minutes, range 0 to 59 
    int min; 
    // hours, range 0 to 23 
    int hour; 
    // day of the month, range 1 to 31 
    int mday; 
    // month, range 0 to 11 
    int mon; 
    // The number of years since 1900 
    int year; 
    // day of the week, range 0 to 6 
    int day; 
    // day in the year, range 0 to 365 
    int yday; 
    // daylight saving time 
    int isdst; 

}owntime;


typedef  struct connection {
    struct in_addr clientIP;//IPV4 address

    uint16_t clientPort;
    struct in_addr serverIP;//IPV4 address

    uint16_t serverPort;
    struct connection *next;//pointer to a next connection
    int state;//current state of a connection
    
    long int byteCnt;//all the bytes from ssl that are not from ssl headers
    int packetCnt;//packet count
    char serverName[HOSTLENGHT];//DNS hostname can have up to only HOSTLENGHT
    long double duration;

    //time formats
    struct tm *startPacketTimestamp;
    unsigned long startMicros;
    struct tm *endPAcketTimestamp;  
    unsigned long endMicros;  
    owntime startTime;
    owntime endTime;

    //IP6
    bool isIP6;
    char clientIPchar[INET6_ADDRSTRLEN];
    char serverIPchar[INET6_ADDRSTRLEN];//will work with chars

}connection;


connection *globalConnections=NULL;

/*List of all functions*/


//function to compute the lenght of a connection
void computeDuration(connection *ptr){//TODO mornin
    //probably should just use the arr
    //year,month,day,hour,minutes,seconds,microseconds

    unsigned long seconds=0;
    
    double result;
    double end;
    double start;

    //some connectino can theoretically have moths and years
    //but i don't think it'll be tested 
    seconds=seconds+(ptr->endTime.year - ptr->startTime.year)*31536000;
    seconds=seconds+(ptr->endTime.mon- ptr->startTime.mon)*86400*28;//fuck i gotta count with different months
    seconds=seconds+(ptr->endTime.mday - ptr->startTime.mday)*86400;
    seconds=seconds+(ptr->endTime.hour- ptr->startTime.hour)*3600;
    seconds=seconds+(ptr->endTime.min - ptr->startTime.min)*60;
    seconds=seconds+ptr->endTime.sec - ptr->startTime.sec;
    //micros=ptr->endMicros - ptr->startMicros;
    //probably just use the float
    end=ptr->endMicros*0.000001;
    start=ptr->startMicros*0.000001;
    result=seconds*1.0+(end-start);
    printf("%.6f", result);
    
}

//prints one connection
void printConnectionSingle(connection *ptr){
    if(ptr->isIP6==false && ptr->state==CLOSED){

            printf("%d-", ptr->startTime.year+1900);
            printf("%02d-", ptr->startTime.mon+1);
            printf("%02d ", ptr->startTime.mday);
            printf("%02d:", ptr->startTime.hour);
            printf("%02d:", ptr->startTime.min);
            printf("%02d.", ptr->startTime.sec);
            printf("%06d,", ptr->startMicros);
            printf("%s,",inet_ntoa(ptr->clientIP));
            printf("%d,",ptr->clientPort);
            printf("%s,",inet_ntoa(ptr->serverIP));
            printf("%s,",ptr->serverName);
            printf("%ld,", ptr->byteCnt);
            printf("%d,",ptr->packetCnt);
            computeDuration(ptr);
            printf("\n");
    }
    else if (ptr->isIP6==true && ptr->state==CLOSED){
           
            printf("%d-", ptr->startTime.year+1900);//TODO format the timestamp
            printf("%02d-", ptr->startTime.mon+1);
            printf("%02d ", ptr->startTime.mday);
            printf("%02d:", ptr->startTime.hour);
            printf("%02d:", ptr->startTime.min);
            printf("%02d.", ptr->startTime.sec);
            printf("%06d,", ptr->startMicros);

            
            printf("%s,",ptr->clientIPchar);
            printf("%d,",ptr->clientPort);
            
            printf("%s,",ptr->serverIPchar);
            
            printf("%s,",ptr->serverName);
            
            printf("%ld,", ptr->byteCnt);
            printf("%d,",ptr->packetCnt);
            computeDuration(ptr);
            printf("\n");
        }

}

void printConnections(){
    connection *ptr=globalConnections;
    int i=0;
    while (ptr!=NULL){

        //YYYY-MM-DD HH:MM:SS.MILISECOND
        
        if(ptr->isIP6==false && ptr->state==CLOSED){
            i++;
            
            printf("%d-", ptr->startTime.year+1900);//TODO format the timestamp
            printf("%02d-", ptr->startTime.mon+1);
            printf("%02d ", ptr->startTime.mday);
            printf("%02d:", ptr->startTime.hour);
            printf("%02d:", ptr->startTime.min);
            printf("%02d.", ptr->startTime.sec);
            printf("%d,", ptr->startMicros);
            printf("%s,",inet_ntoa(ptr->clientIP));
            printf("%d,",ptr->clientPort);
            printf("%s,",inet_ntoa(ptr->serverIP));
            printf("%s,",ptr->serverName);
            printf("%ld,", ptr->byteCnt);
            printf("%d,",ptr->packetCnt);
            computeDuration(ptr);
            printf("\n");
        }
        else if (ptr->isIP6==true && ptr->state==CLOSED){
            i++;
            
            printf("%d-", ptr->startTime.year+1900);//TODO format the timestamp
            printf("%02d-", ptr->startTime.mon+1);
            printf("%02d ", ptr->startTime.mday);
            printf("%02d:", ptr->startTime.hour);
            printf("%02d:", ptr->startTime.min);
            printf("%02d.", ptr->startTime.sec);
            printf("%d,", ptr->startMicros);

            //printf("Client:");
            printf("%s,",ptr->clientIPchar);
            printf("%d,",ptr->clientPort);
            //printf("    Server:");
            printf("%s,",ptr->serverIPchar);
            //printf("%d, ",ptr->serverPort);
            printf("%s,",ptr->serverName);
            
            printf("%ld,", ptr->byteCnt);
            printf("%d,",ptr->packetCnt);
            computeDuration(ptr);
            printf("\n");
        }
        

        
        ptr=ptr->next;
    }
    

}

void clearArray(char c[],int lenght){//TODO
    for (int i = 0; i < lenght; i++)
        c[i]='\0';

}


/*
    +++++++++++++++++++++++++++++++
    + SYN + FIN + RST + PUSH +ACK +
    +++++++++++++++++++++++++++++++
*/

void findMessage(const struct tcphdr *tcpPacket , int *messageTCP){
    if (tcpPacket->th_flags & TH_SYN)
        *messageTCP|=SYN;
    if (tcpPacket->th_flags & TH_FIN)
        *messageTCP|=FIN;
    if (tcpPacket->th_flags & TH_RST)
        *messageTCP|=RST;
    if (tcpPacket->th_flags & TH_PUSH)
        *messageTCP|=PUSH;
    if (tcpPacket->th_flags & TH_ACK)
        *messageTCP|=ACK;
}


connection *checkConnections(const struct tcphdr *tcpPacket, struct ip *my_ip, const struct ip6_hdr *ipv6_header){//here is a problem
    connection *ptr=globalConnections;

    
    while(ptr!=NULL){//iterates the linked-list 
        
        if (my_ip!=NULL){
            
            //it should contain just two adresses and should not be the same

            if (my_ip->ip_src.s_addr == ptr->clientIP.s_addr || my_ip->ip_dst.s_addr == ptr->clientIP.s_addr ){//ip comparison
                if(my_ip->ip_src.s_addr == ptr->serverIP.s_addr || my_ip->ip_dst.s_addr == ptr->serverIP.s_addr){
                   
                    if (ntohs(tcpPacket->th_dport)==ptr->clientPort || ntohs(tcpPacket->th_sport)==ptr->clientPort ){//port comparison, beacause there can be different ports and connections
                        if (ntohs(tcpPacket->th_dport)==ptr->serverPort || ntohs(tcpPacket->th_sport)==ptr->serverPort ){
                            return ptr;
                        }
                    }
                }
            }//long spagetti but it's workin
        }
        else if (ipv6_header!=NULL){
            
            char ip6_src[INET6_ADDRSTRLEN]={};
            char ip6_dst[INET6_ADDRSTRLEN]={};
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ip6_src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ip6_dst, INET6_ADDRSTRLEN);
            
            //    if(strcmp(inet_ntop(AF_INET6, &(ipv6_header->ip6_src), NULL, INET6_ADDRSTRLEN), ptr->clientIPchar)==0  || strcmp(inet_ntop(AF_INET6, &(ipv6_header->ip6_src), NULL, INET6_ADDRSTRLEN)){}
            if (strcmp(ip6_src, ptr->clientIPchar)==0 || strcmp(ip6_dst, ptr->clientIPchar)==0 ){
                if (strcmp(ip6_src, ptr->serverIPchar)==0 || strcmp(ip6_dst, ptr->serverIPchar)==0 ){
                    if (ntohs(tcpPacket->th_dport)==ptr->clientPort || ntohs(tcpPacket->th_sport)==ptr->clientPort ){//port comparison, beacause there can be different ports and connections
                        if (ntohs(tcpPacket->th_dport)==ptr->serverPort || ntohs(tcpPacket->th_sport)==ptr->serverPort ){
                            return ptr;
                        }
                    }
                }
            }
        }
        
        ptr=ptr->next;
    }
    return NULL;

}

bool comesFromServer(struct ip *my_ip, connection *ptr,const struct tcphdr *tcpPacket, const struct ip6_hdr *ipv6_header){
    if(my_ip!=NULL)
        return (ptr->serverIP.s_addr==my_ip->ip_src.s_addr && ntohs(tcpPacket->th_sport)==ptr->serverPort) ?  true : false;

    else if(ipv6_header!=NULL){
        char ip6_src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ip6_src, INET6_ADDRSTRLEN);
        return (strcmp(ip6_src, ptr->serverIPchar) == 0 &&ntohs(tcpPacket->th_sport)==ptr->serverPort) ? true : false;
    }
        
}
bool comesFromClient(struct ip *my_ip, connection *ptr, const struct tcphdr *tcpPacket, const struct ip6_hdr *ipv6_header){
    if(my_ip!=NULL)
        return (ptr->clientIP.s_addr==my_ip->ip_src.s_addr && ntohs(tcpPacket->th_sport)==ptr->clientPort) ?  true : false;
    
    else if(ipv6_header!=NULL){
        char ip6_src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ip6_src, INET6_ADDRSTRLEN);
        return (strcmp(ip6_src, ptr->clientIPchar)==0 && ntohs(tcpPacket->th_sport)==ptr->clientPort)  ? true : false;
    }
    
}
//copy foos for copying to my own struct
//did it beacause of pointer bug
void copytime(connection *ptr, struct tm *timestamp){
    ptr->startTime.year=timestamp->tm_year;
    ptr->startTime.mon=timestamp->tm_mon;
    ptr->startTime.mday=timestamp->tm_mday;
    ptr->startTime.hour=timestamp->tm_hour;
    ptr->startTime.min=timestamp->tm_min;
    ptr->startTime.sec=timestamp->tm_sec;   
}

void copytimeEnd(connection *ptr, struct tm *timestamp){
    ptr->endTime.year=timestamp->tm_year;
    ptr->endTime.mon=timestamp->tm_mon;
    ptr->endTime.mday=timestamp->tm_mday;
    ptr->endTime.hour=timestamp->tm_hour;
    ptr->endTime.min=timestamp->tm_min;
    ptr->endTime.sec=timestamp->tm_sec;   
}
//appends connection struct to a list
bool appendAndCreateConnection(const struct tcphdr *tcpPacket, struct ip *my_ip, struct tm *timestamp, unsigned long time_in_micros, const struct ip6_hdr *ipv6_header){//adds connection and initialize the state

    connection *ptr=globalConnections;
    connection *ptr2;
    while(ptr!=NULL){
        ptr2=ptr->next;
        if(ptr2==NULL){
            
            if (my_ip!=NULL){
                ptr2=malloc(sizeof(struct connection));
                ptr->next=ptr2;

                int messageTCP=0b0;
                ptr2->next=NULL;
                ptr2->clientIP=my_ip->ip_src;
                ptr2->serverIP=my_ip->ip_dst;
                ptr2->clientPort=ntohs(tcpPacket->th_sport);
                ptr2->serverPort=ntohs(tcpPacket->th_dport);
                ptr2->startPacketTimestamp=timestamp;
                //TODOTIME
                copytime(ptr2,timestamp);
                ptr2->startMicros=time_in_micros;
                //should return true;
                findMessage(tcpPacket,&messageTCP);
                if (messageTCP==SYN){
                    ptr2->state=START;
                } 
                clearArray(ptr2->serverName,HOSTLENGHT);
                return true;

            }
            else if(ipv6_header!=NULL){
                ptr2=malloc(sizeof(struct connection));
                ptr->next=ptr2;

                int messageTCP=0b0;
                ptr2->next=NULL;
                inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ptr2->clientIPchar, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ptr2->serverIPchar, INET6_ADDRSTRLEN);
                

                ptr2->clientPort=ntohs(tcpPacket->th_sport);
                ptr2->serverPort=ntohs(tcpPacket->th_dport);
                ptr2->startPacketTimestamp=timestamp;
                //TODOTIME
                copytime(ptr2,timestamp);
                ptr2->startMicros=time_in_micros;
                ptr2->isIP6=true;
                
                findMessage(tcpPacket,&messageTCP);
                if (messageTCP==SYN){
                    ptr2->state=START;
                } 
                return true;
            }
        }

        ptr=ptr->next;

    }
}


void createConnectionStart(const struct tcphdr *tcpPacket, struct ip *my_ip, struct tm *timestamp, unsigned long time_in_micros, const struct ip6_hdr *ipv6_header){

    if (tcpPacket->th_flags & TH_SYN && my_ip!=NULL){
        int messageTCP=0b0;
        globalConnections=malloc(sizeof(struct connection));
        globalConnections->next=NULL;
        globalConnections->clientIP=my_ip->ip_src;
        globalConnections->serverIP=my_ip->ip_dst;
        globalConnections->clientPort=ntohs(tcpPacket->th_sport);
        globalConnections->serverPort=ntohs(tcpPacket->th_dport);
        //find wheter it is a SYN packet
        globalConnections->startPacketTimestamp=timestamp;
        //TODOTIME
        copytime(globalConnections,timestamp);
        
        globalConnections->startMicros=time_in_micros;
        globalConnections->isIP6=false;
        
        findMessage(tcpPacket,&messageTCP);
        if (messageTCP==SYN){
            globalConnections->state=START;
        }    
        
        ;
    }
    else if(tcpPacket->th_flags & TH_SYN && ipv6_header!=NULL){
        
        int messageTCP=0b0;
        globalConnections=malloc(sizeof(struct connection));
        globalConnections->next=NULL;
        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), globalConnections->clientIPchar, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), globalConnections->serverIPchar, INET6_ADDRSTRLEN);

        globalConnections->clientPort=ntohs(tcpPacket->th_sport);
        globalConnections->serverPort=ntohs(tcpPacket->th_dport);
        globalConnections->startPacketTimestamp=timestamp;
        //TODOTIME
        copytime(globalConnections,timestamp);
        globalConnections->startMicros=time_in_micros;
        globalConnections->isIP6=true;
        //TODO
        findMessage(tcpPacket,&messageTCP);
        if (messageTCP==SYN){
            globalConnections->state=START;
        }    
        connection *ptr=globalConnections;
    }


}


//read two bytes from payload using shift
int readTwoBytes(int data[], int size,int index){
    int longByte=data[size+index];
    longByte=longByte<<8;
    return longByte+data[size+index+1];
}
//read three bytes from payload using shift
int readThreeBytes(int data[], int size,int index){
    int longByte=data[size+index];
    longByte=longByte<<8;
    longByte=longByte+data[size+index+1];
    longByte=longByte<<8;
    return longByte+data[size+index+2];
}


//data, size, SNI, connection
bool analyzeClientHello(int data[],int size, char serverNameString[], connection *ptr){
    //record header
    //sorry for lots of vars but it was the first try at this function and I didn't have time to make it looks better

    bool status=true;
    long int longByte;
    long int longByte2;
    long int longByte3;
    long int cypherDataLenght;
    long int extentionLenght;
    long int serverDataLenght;
    long int serverNameListLength;
    long int SNIlength;


    char serverName[HOSTLENGHT]={};

    

    int internByteIndex;
    
    if (data[size]==0x16 && data[size+1]==0x03)//watch out for versions   
        status=true;
    else 
        return false;
    
    longByte=readTwoBytes(data,size,3);//bytes of handshake message follows 
    ptr->byteCnt=longByte;
    //
    if (data[size+5]==0x01)//maybe I should strat incrementing some var and not to use some 
        status=true;
    else 
        return false;

    longByte2=readThreeBytes(data,size,6);//this much data follows
    if (readTwoBytes(data,size,9)==0x0303)
        status=true;
    else 
        return false;
    //then there are 32 bytes of random data 10+32
    internByteIndex=42;

    //Session ID
    longByte3=data[size+internByteIndex+1];//bytes of data follow
    internByteIndex=internByteIndex+longByte3+1;


    //two bytes of cipher Suites data follows
    cypherDataLenght=readTwoBytes(data,size,internByteIndex+1);//k it works
    internByteIndex=internByteIndex+cypherDataLenght+1;

    //compression but compresion is not used anymore because it 
    internByteIndex=internByteIndex+2;//because it is spread among 2 bytes


    //Extention
    extentionLenght=readTwoBytes(data,size,internByteIndex+2);//it will take that amout of data
    if(readTwoBytes(data,size,internByteIndex+4)==0x00){ //it is in a first extension
        status=true;///0x00 indicates tha it is a server name
        serverDataLenght=readTwoBytes(data,size,internByteIndex+6);//19bytes on google
        serverNameListLength=readTwoBytes(data,size,internByteIndex+8);//should be serverDataLenght-2
        if(data[size+internByteIndex+10]==0x00) status=true;///0x00 indicates tha it is a host_name
        else return false;


        //finally SNI
        SNIlength=readTwoBytes(data,size,internByteIndex+11);
        
        //serverName=malloc(sizeof(char)*SNIlength);
        //serverName='\0';
        internByteIndex=internByteIndex+13;
        clearArray(serverName,SNIlength); clearArray(serverNameString,SNIlength);

        for (int i=0;i<SNIlength;i++){
            serverName[i]=data[size+internByteIndex+i];
        }

        for (int i=SNIlength;i<HOSTLENGHT;i++){
            serverName[i]='\0';
        }
        
        
        strcpy(serverNameString,serverName);


    }
    else {
        //find in a extentions
        int jumpLenght=readTwoBytes(data,size,internByteIndex+6);
        internByteIndex=internByteIndex+8+jumpLenght;//8 because of byte shift
        
        

        if(readTwoBytes(data,size,internByteIndex)==0x00 && data[size+internByteIndex+6]==0x00){
            //serverNameLenght
            status=true;
            SNIlength=readTwoBytes(data,size,internByteIndex+7);//should be 23bytes in packet No.7 ipv6-mess.pcapng
            internByteIndex=internByteIndex+9;
            

            for (int i=0;i<SNIlength;i++){
                serverName[i]=data[size+internByteIndex+i];
            }
            strcpy(serverNameString,serverName);
            //printf("%s", serverName);

        }
            
    }
    

    


    return status;
}   

//can have multiple tls header 
//gotta catch them all
bool analyzeServerHello(int data[],int size, char *serverName, u_int packetByteLenght, connection *ptr){//server hello can have more messages so check those
    int internByteIndex;
    bool status;
    long int lengthLayer;
    long int dataLength;
    long int CypherLenght;
    long int appLengnth;

    //long int byteCount=0;

    bool isHeader;

    long int byteCountVar=0;

    long int jumpLenght;

    if (data[size]==0x16 && data[size+1]==0x03)  //watch oput for data it doesn't really matter and it should be alright
        status=true;
    else 
        return false;
    
    lengthLayer=readTwoBytes(data,size,3);
    byteCountVar=byteCountVar+readTwoBytes(data,size,3);

    if(data[size+5]==0x02) status=true;//it is a server hello//it is in stnadalone "layer"
    else return false;

    //add the bytelenght


    internByteIndex=lengthLayer+5;
    
    //now try write the recursive function

    for (size_t i = size+internByteIndex; i < packetByteLenght; i++){
        if (data[i]>=0x14 && data[i]<=0x17
                    && data[i+1]==0x03 && data[i+2]>=0x1
                    && data[i+2]<=0x04 
                    /*&& readTwoBytes(data,i,i+3)>0x00/**/
            ){
                jumpLenght=readTwoBytes(data,0,i+3);
                byteCountVar=byteCountVar+readTwoBytes(data,0,i+3);
                i=i+jumpLenght;//it will jump over the data
                //printf("hey there is a header\n");
        }
    }
    ptr->byteCnt=ptr->byteCnt+byteCountVar;

    return status;
}  

bool analyzeEstablishedConnectionHeadears(int data[],int size, char *serverName, u_int packetByteLenght, connection *ptr){
    //can be up to three app data layers
    //can be also on the beggining of a packet
    bool status;
    int internByteIndex;
    int debugLenght;
    int jumpLenght;
    
    //"Byte window"
    /*
    1. byte -0x14 to 0x17
    2-3. byte - 0x301 to 0x304
    4- 5. byte gotta exists 
    as a lenght
    */
    int dataLenght=0;
    
    for(int i=size;i<packetByteLenght;i++){
        if (data[i]>=0x14 && data[i]<=0x17
            && data[i+1]==0x03 && data[i+2]>=0x1
            && data[i+2]<=0x04 ){ 
                                          
            jumpLenght=readTwoBytes(data,0,i+3);
            
            dataLenght=dataLenght+readTwoBytes(data,0,i+3);
            i=i+jumpLenght;//to jump over data

            }
        }

    ptr->byteCnt=ptr->byteCnt+dataLenght;
    return status;

}

//v podstate konečný automat
void FSmach(const struct tcphdr *tcpPacket , struct ip *my_ip, u_int lenght,  int data[],int size, struct tm *timestamp, unsigned long time_in_micros, const struct ip6_hdr *ipv6_header){
    int messageTCP=0;
    


    if (globalConnections==NULL)//there are no connections
        //creates the first connection in the global linked-list
        createConnectionStart(tcpPacket, my_ip, timestamp, time_in_micros, ipv6_header);
    
    else{
        //there are some connections
        //iterate through connections and compare, if it finds FS starts
        connection *ptrMain= checkConnections(tcpPacket, my_ip, ipv6_header);
        if(ptrMain!=NULL){//it has found a connection //it should also return a pointer to a connection
            
            
            findMessage(tcpPacket, &messageTCP);//Gets flags and save it to messageTCP

            switch (ptrMain->state){
            case START://the connection was established and it also has an SYN message
                /* code */
                if (messageTCP == (SYN | ACK) && comesFromServer(my_ip, ptrMain, tcpPacket, ipv6_header)){//shlould also found out wheter it is from server or a client
                    ptrMain->packetCnt=2;//2 because SYN must've already be there
                    ptrMain->state=SERVER_SYN_ACK;
                }
                break;

            case SERVER_SYN_ACK:
                if (messageTCP == ACK && comesFromClient(my_ip,ptrMain, tcpPacket, ipv6_header)){//shlould also found out wheter it is from server or a client
                    //
                    ptrMain->packetCnt++;
                    ptrMain->state=CLIENT_ACK;
                }
                break;
            case CLIENT_ACK:
                if (messageTCP == (ACK | PUSH) && comesFromClient(my_ip,ptrMain,tcpPacket, ipv6_header)){
                    
                    //should also return a 
                    clearArray(&ptrMain->serverName,HOSTLENGHT);
                    //long int bytecount;
                    analyzeClientHello(data,size,ptrMain->serverName, ptrMain);
                    //ptrMain->byteCnt=ptrMain->byteCnt+bytecount;
                    ptrMain->packetCnt++;
                    ptrMain->state=SERVER_HELLO;
                }                
                break;
            
            case SERVER_HELLO://waiting for server hello
                //here is a bug
                if ( messageTCP == ( PUSH | ACK) || messageTCP == ACK && comesFromServer(my_ip,ptrMain,tcpPacket, ipv6_header)){
                    
                    if(analyzeServerHello(data,size,ptrMain->serverName, lenght, ptrMain)) 
                        ptrMain->state=CONNECTION_EST;//check wheter it is a true
                    else 
                        ptrMain->state=SERVER_HELLO;
                    ptrMain->packetCnt++;
                    
                }
                else if (messageTCP == ACK){//if it is just ACK and waits for the server_hello
                    ptrMain->state=SERVER_HELLO;
                    ptrMain->packetCnt++;
                }
    
                break;

            case CONNECTION_EST:
                
                if(messageTCP==ACK){
                    //printf("now we are gettin the ACK\n");
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);//because even in ack can be some TLS headers
                    ptrMain->packetCnt++;
                }
                else if (messageTCP ==  ( PUSH | ACK)){
                    
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);
                    ptrMain->packetCnt++;
                }
                else if (messageTCP ==  (FIN | ACK) || messageTCP ==  (FIN | PUSH | ACK)  ){
                    
                    //check wheter there are any data
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);
                    ptrMain->packetCnt++;
                    ptrMain->endPAcketTimestamp=timestamp;
                    copytimeEnd(ptrMain,timestamp);
                    ptrMain->endMicros=time_in_micros;
                    ptrMain->state=FIN_FIRST;
                }
                else if (messageTCP ==  (RST | ACK) || messageTCP ==  (RST)  ){
                    
                    //check wheter there are any data
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);
                    ptrMain->packetCnt++;
                    ptrMain->endPAcketTimestamp=timestamp;
                    copytimeEnd(ptrMain,timestamp);
                    ptrMain->endMicros=time_in_micros;
                    ptrMain->state=CLOSED;
                    //if(isFile==false)
                        printConnectionSingle(ptrMain);
                }
                
                break;
            case FIN_FIRST:
                //maybe should use switch

                
                if (messageTCP== (FIN | ACK | PUSH) || messageTCP== (FIN | ACK ) || messageTCP== (FIN | PUSH | ACK ) ){
                    //printf("Now we should close it\n");
                    ptrMain->packetCnt++;
                    ptrMain->endPAcketTimestamp=timestamp;
                    copytimeEnd(ptrMain,timestamp);
                    ptrMain->endMicros=time_in_micros;
                    ptrMain->state=CLOSED;
                    //if(isFile==false)
                        printConnectionSingle(ptrMain);
                    //now we should print out the single connection
                }
                else if (messageTCP== (ACK) || messageTCP ==  ( PUSH | ACK)){//even ack could be last packet tha's why i always "refresh" the time data
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);
                    ptrMain->packetCnt++;
                    ptrMain->endPAcketTimestamp=timestamp;
                    copytimeEnd(ptrMain,timestamp);
                    
                }
                else if (messageTCP ==  (RST | ACK) || messageTCP ==  (RST)){
                    //printf("Now we should close it\n");
                    //check wheter there are any data
                    analyzeEstablishedConnectionHeadears(data,size,ptrMain->serverName, lenght, ptrMain);
                    ptrMain->packetCnt++;
                    ptrMain->endPAcketTimestamp=timestamp;
                    ptrMain->endMicros=time_in_micros;
                    copytimeEnd(ptrMain,timestamp);
                    ptrMain->state=CLOSED;
                    //if(isFile==false)
                        printConnectionSingle(ptrMain);
                }
                break;
            case CLOSED:

                break;
            default:
                break;
            }

        }
        else{//creates new connection to a linked list
            
            //if it is a new connection it should have a SYN packet 
            if (tcpPacket->th_flags & TH_SYN){
                if (appendAndCreateConnection(tcpPacket, my_ip, timestamp, time_in_micros, ipv6_header))
                    ;
                
            }
            

        }
    }

}



int main(int argc, char *argv[]){
    int pckCnt;
    char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
    char errbuf2[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct ip *my_ip;
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    struct pcap_pkthdr header;
    struct pcap_pkthdr *header2;

    struct ether_header *eptr;
    pcap_t *handle;        
    pcap_t *handle2;         // file/device handler
    u_int size_ip;
    u_int size_tcp;

    int returnValue;
    
    const char *payload;
    const u_char *data;

    int *dataAnalysis;
    
    //live capture vars
    
    pcap_if_t *alldev, *dev ;       // a list of all input devices

    //vars for ipv6 header
    const struct ip6_hdr *ipv6_header;



    //my device: wlp5s0
    //arguments processing
    switch (argc){
    case 3:
        //gets args
        if(strcmp("-r",argv[1])==0)
            isFile=true;
        else if(strcmp("-i",argv[1])==0)
            isFile=false;
        
        break;
    
    default://prints help

        printf("ARGS: ./sslsniff [-r <file>] [-i interface] \n");
        printf("-r:  pcapng file\n");
        printf("-i:  intefrface to listen and analyze to\n");

        break;
    }

    
    if(isFile){//reading from pcapng
        
        //also this is used from garat's demo
        if ((handle = pcap_open_offline(argv[2],errbuf)) == NULL)
            err(1,"Can't open file for reading");
        if ((handle2 = pcap_open_offline(argv[2],errbuf2)) == NULL)
            err(1,"Can't open file for reading");/**/
    }
    else{//live capture

        //FIND availabe devices
        //some of this code was used from prof. Matousek
        
        isFile=false;

        if (pcap_findalldevs(&alldev, errbuf))
            err(1,"Can't open input device(s)");
        for (dev = alldev; dev != NULL; dev = dev->next){

            if(strcmp(dev->name,argv[2])==0){//controls the available network devices
                if ((handle = pcap_open_live(argv[2],BUFSIZ,1,1000,errbuf)) == NULL)
                    err(1,"pcap_open_live() failed\n");
        
                if ((handle2 = pcap_open_live(argv[2],BUFSIZ,1,1000,errbuf)) == NULL)
                    err(1,"pcap_open_live() failed\n");
            }
        }

        
    }

    //printf("Opening file %s for reading ...\n\n", argv[1]);
    pckCnt = 0;//used for debugging
    
    // read packets from the file
    //had to use pcap_net() for loop and pcap_next_ex 
    //this cycle was used by garant
    while ((packet = pcap_next(handle,&header)) != NULL){

        returnValue = pcap_next_ex(handle2, &header2, &data);//using this function to get data 
        

        pckCnt++;
        
        // read the Ethernet header
        eptr = (struct ether_header *) packet;
        my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
        size_ip = my_ip->ip_hl*4;                           // length of IPv4 header
        
        //these vars are used for link-layer 
        struct tm *timestamp = localtime(&header.ts.tv_sec);
        unsigned long time_in_micros = header.ts.tv_usec;

        switch (ntohs(eptr->ether_type)){              
            case ETHERTYPE_IP: // IPv4 packet            
            switch (my_ip->ip_p){

                case 6: ;// TCP protocol
                    //DEBUG
                                        
                    struct tm *timestamp = localtime(&header.ts.tv_sec);
            
                    unsigned long int time_in_micros = header.ts.tv_usec;//k it is done
                
                    my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
                    size_tcp = my_tcp->th_off*4;//this is a header lenght
                    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);//gets to the payload
                    int size = SIZE_ETHERNET + size_ip + size_tcp;///size of all protocols before tls that means eth+ip+tcp this does not include the tcp payload because tls is stored in it
                    
                    

                    u_int lenght=header2->caplen;
                    dataAnalysis=malloc(sizeof(int)*lenght);

                    
                    /*for (u_int i=0; i < header2->caplen  ; i++){
                        if ( (i % 16) == 0) printf("\n");
                        printf("%.2x ", data[i]);   
                    }/**/
                    for (u_int i=0; i < header2->caplen  ; i++)
                        dataAnalysis[i]=data[i];
                    
                    
                    /**/
                    FSmach(my_tcp, my_ip,header2->caplen,dataAnalysis,size, timestamp, time_in_micros,NULL);
                    //DEBUG
                    /*
                    if (my_tcp->th_flags & TH_SYN)
                        printf(", SYN");
                    if (my_tcp->th_flags & TH_FIN)
                        printf(", FIN");
                    if (my_tcp->th_flags & TH_RST)
                        printf(", RST");
                    if (my_tcp->th_flags & TH_PUSH)
                        printf(", PUSH");
                    if (my_tcp->th_flags & TH_ACK)
                        printf(", ACK");
                    printf("\n");
                    /**/
                    break;
            } 
            break;
            case ETHERTYPE_IPV6:
                
                /**/
                //IP header

                //printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
                ipv6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header)); 

                my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip+sizeof(struct ip6_hdr));
                
                u_int lenght=header2->caplen;
                dataAnalysis=malloc(sizeof(int)*lenght);
                for (u_int i=0; i < header2->caplen  ; i++){
                    dataAnalysis[i]=data[i];
                }
                size_tcp = my_tcp->th_off*4;//this is a header lenght
                payload = (u_char *)(packet + SIZE_ETHERNET + sizeof(struct ip6_hdr) + size_tcp);
                int size = SIZE_ETHERNET + sizeof(struct ip6_hdr) + size_tcp;
                

                
                if (ipv6_header->ip6_nxt== IPPROTO_TCP){//TCP
                    FSmach(my_tcp, NULL, header2->caplen, dataAnalysis, size, timestamp, time_in_micros, ipv6_header);
                }
            
               
                
                //now i should get to tcp data and then to analysis but needs to rework addresses to strings

            break;
        }
        
    }

    //if (isFile)
    //    printConnections();

    //lasr revision 23:21
    pcap_close(handle);
    free(globalConnections);
    return 0;
    
}
