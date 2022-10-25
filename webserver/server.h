#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/file.h>
#include <fcntl.h>

/* Defines */
#define DHCP_OPTIONS 		"BOOTPROTO="
#define IP_STRING	 		"IP="
#define SUBNET_STRING	 	"NETMASK="
#define BROADCAST_STRING	"BROADCAST="
#define NETWORK_STRING		"NETWORK="
#define GATEWAY_STRING		"GATEWAY="

/* Variables */
typedef struct{
    int addr1;
    int addr2;
    int addr3;
    int addr4;
}networkAddr;

typedef struct{
	int dhcp;
    networkAddr ip;
    networkAddr sn;
    networkAddr gw;
}formValues;


/* Index */
void Log(char *filename, char *content);
int parseForm(char* form, formValues * result);
void changeIP(formValues * networkParam);
void b64_encode(char *clrstr, char *b64dst);
void b64_decode(char *b64src, char *clrdst);

/* Implementation */
void Log(char *filename, char *content)
{
	FILE * fd = fopen(filename, "a+");
	fprintf(fd, "%s\n", content);
	fclose(fd);
}

int parseForm(char* form, formValues * result)
{
	unsigned int qty = 0, i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);

	char *values = malloc(nParam*256*sizeof(char));
	
	char *strValue, tmpValue[10];
	unsigned char valueLen;
	
	strValue = strstr(form,"ip1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr1 = atoi(tmpValue);
	strValue = strstr(form,"ip2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr2 = atoi(tmpValue);
	strValue = strstr(form,"ip3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr3 = atoi(tmpValue);
	strValue = strstr(form,"ip4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->ip.addr4 = atoi(tmpValue);
	strValue = strstr(form,"sn1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->sn.addr1 = atoi(tmpValue);
	strValue = strstr(form,"sn2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->sn.addr2 = atoi(tmpValue);
	strValue = strstr(form,"sn3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->sn.addr3 = atoi(tmpValue);		
	strValue = strstr(form,"sn4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->sn.addr4 = atoi(tmpValue);
	strValue = strstr(form,"gw1=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)	
		result->gw.addr1 = atoi(tmpValue);
	strValue = strstr(form,"gw2=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr2 = atoi(tmpValue);
	strValue = strstr(form,"gw3=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr3 = atoi(tmpValue);
	strValue = strstr(form,"gw4=");
	for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
		;
	strncpy(tmpValue,strValue+4,valueLen);
	if(strValue != NULL)
		result->gw.addr4 = atoi(tmpValue);		
	if(strstr(form,"dhcp=on"))
		result->dhcp = 1;
	else if(strstr(form,"dhcp=off"))
		result->dhcp = 0;		


	char logString[256];
	sprintf(logString,"New network config:\nDHCP:%d\nIP:%d.%d.%d.%d\nSN:%d.%d.%d.%d\nGW:%d.%d.%d.%d\n",result->dhcp,
																		result->ip.addr1,result->ip.addr2,result->ip.addr3,result->ip.addr4,
																		result->sn.addr1,result->sn.addr2,result->sn.addr3,result->sn.addr4,
																		result->gw.addr1,result->gw.addr2,result->gw.addr3,result->gw.addr4);
	printf(logString);

	free(values);

    return qty;   
}

void changeIP(formValues * networkParam)
{
	FILE * fd = fopen("/etc/network/network.conf","r");
	//FILE * fd = fopen("/home/utente/network.conf","r");
	char ip[18], sn[18], gw[18], broadcast[18], network[18], dhcp[2][17], networkFile[30][100];
	int index = 0, i;

	if(fd != NULL)
	{
		
		sprintf(ip,"\"%d.%d.%d.%d\"",networkParam->ip.addr1, networkParam->ip.addr2, networkParam->ip.addr3, networkParam->ip.addr4);
		sprintf(sn,"\"%d.%d.%d.%d\"",networkParam->sn.addr1, networkParam->sn.addr2, networkParam->sn.addr3, networkParam->sn.addr4);
		sprintf(gw,"\"%d.%d.%d.%d\"",networkParam->gw.addr1, networkParam->gw.addr2, networkParam->gw.addr3, networkParam->gw.addr4);		
		sprintf(broadcast,"\"%d.%d.%d.%d\"",
							(networkParam->sn.addr1 & networkParam->ip.addr1), 
							(networkParam->sn.addr2 & networkParam->ip.addr2), 
							(networkParam->sn.addr3 & networkParam->ip.addr3), 
							(networkParam->sn.addr4 & networkParam->ip.addr4) | (0xFF ^ networkParam->sn.addr4));		
		sprintf(network,"\"%d.%d.%d.%d\"",
							(networkParam->sn.addr1 & networkParam->ip.addr1), 
							(networkParam->sn.addr2 & networkParam->ip.addr2), 
							(networkParam->sn.addr3 & networkParam->ip.addr3), 
							(networkParam->sn.addr4 & networkParam->ip.addr4));		
		sprintf(dhcp[0],"BOOTPROTO=\"none\"");
		sprintf(dhcp[1],"BOOTPROTO=\"dhcp\"");

		while(fgets(networkFile[index++],100,fd))
		{
			Log("/tmp/webserver.log",networkFile[index-1]);
			if(strncmp(networkFile[index-1],DHCP_OPTIONS,strlen(DHCP_OPTIONS))==0)
			{			
				sprintf(networkFile[index-1],"%s\n",dhcp[networkParam->dhcp]);			
			}
			else if(strncmp(networkFile[index-1],IP_STRING,strlen(IP_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",ip);			
			}
			else if(strncmp(networkFile[index-1],SUBNET_STRING,strlen(SUBNET_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",sn);			
			}
			else if(strncmp(networkFile[index-1],BROADCAST_STRING,strlen(BROADCAST_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n", broadcast);				
			}
			else if(strncmp(networkFile[index-1],NETWORK_STRING,strlen(NETWORK_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n", network);				
			}
			else if(strncmp(networkFile[index-1],GATEWAY_STRING,strlen(GATEWAY_STRING))==0)
			{
				sprintf(strchr(networkFile[index-1], '"'),"%s\n",gw);			
			}
		}

		fclose(fd);

		//fd = fopen("/home/utente/network.conf","w");	
		fd = fopen("/etc/network/network.conf","w");	
		if(fd != NULL)
		{
			for(i=0;i<index;i++)
				fwrite(networkFile[i],1,strlen(networkFile[i]),fd);

			fclose(fd);	
			system("reboot");
		}
		else
			printf("Errore apertura file network.conf in scrittura\n");
	}
	else
		printf("Errore apertura file network.conf in lettura\n");

}


/* ---- Base64 Encoding/Decoding Table --- */
	char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char *clrstr) {
	unsigned char out[4];
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
	out[3] = '\0';
	strncat(clrstr, (char *)out, sizeof(out));
}

void b64_decode(char *b64src, char *clrdst) {
	int c, phase, i;
	unsigned char in[4];
	char *p;

	clrdst[0] = '\0';
	phase = 0; i=0;
	while(b64src[i]) {
		c = (int) b64src[i];
		if(c == '=') {
			decodeblock(in, clrdst); 
			break;
		}
		p = strchr(b64, c);
		if(p) {
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if(phase == 0) {
				decodeblock(in, clrdst);
				in[0]=in[1]=in[2]=in[3]=0;
			}
		}
		i++;
	}
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock( unsigned char in[], char b64str[], int len ) {
	unsigned char out[5];
	out[0] = b64[ in[0] >> 2 ];
	out[1] = b64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? b64[ ((in[1] & 0x0f) << 2) |
		((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? b64[ in[2] & 0x3f ] : '=');
	out[4] = '\0';
	strncat(b64str, (char *)out, sizeof(out));
}

/* encode - base64 encode a stream, adding padding if needed */
void b64_encode(char *clrstr, char *b64dst) {
	unsigned char in[3];
	int i, len = 0;
	int j = 0;

	b64dst[0] = '\0';
	while(clrstr[j]) {
		len = 0;
		for(i=0; i<3; i++) {
			in[i] = (unsigned char) clrstr[j];
			if(clrstr[j]) {
				len++; j++;
			}
			else in[i] = 0;
		}
		if( len ) {
			encodeblock( in, b64dst, len );
		}
	}
}

/* */
