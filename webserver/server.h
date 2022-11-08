#include <sys/stat.h>
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
#include "file.h"

/* Defines */
#define DHCP_OPTIONS 		"BOOTPROTO="
#define IP_STRING	 		"IP="
#define SUBNET_STRING	 	"NETMASK="
#define BROADCAST_STRING	"BROADCAST="
#define NETWORK_STRING		"NETWORK="
#define GATEWAY_STRING		"GATEWAY="

#define N_BYTES_PARAMS		4096

#define STRING_TYPE			0
#define	INT_TYPE			1

/* Enumeration */
enum {COND_REMOTE=0, COND_ALARM, COND_SABOT, COND_FAIL, COND_EXCL, COND_BYPASS,
      COND_LOC_TAMPER, COND_LOC_POWERFAIL, COND_LOC_BATTFAIL};

/* Type definition */
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
}ipFormValues_t;

typedef struct{
	char connection[4];				/* COM/USB/LAN */
	char serialPort;				/* 0=COM1, 1=COM2, 2=USB1, 3=USB2, 4=USB3 */
	unsigned int plant;
	unsigned int address;
	unsigned int baudrate;
	networkAddr ip;
	unsigned int networkPort;	
	unsigned int numeration;	
	char code[64];					/* for Tecnofire only */
	char passphrase[64];			/* for Tecnofire only */
	unsigned int registerDimension;	/* for DEF only */
	unsigned int polling;
	unsigned char inputBalance;		/* for Saet only */
}centralParam_t;

typedef struct{
	unsigned char function;			/* 0=allarme, 1=guasto, 2=esclusione, 3=bypass */
	char * description;
	unsigned char allDayActive;
	unsigned int delay;
	unsigned char delayType;
	unsigned char restore;
	unsigned char restoreCondition;
}centralInput_t;

typedef struct{
	char centralType[64];
	char centralModel[64];
	centralParam_t centralParam;
	centralInput_t inputs[8];
}isiFormValues_t;

typedef struct{
	
}svFormValues_t;

typedef struct{
	char * username;
	char * oldPassword;
	char * newPassword;
	char * newPassword2;
}credentialFormValues_t;

/* Index */
int searchValIntoForm(char * form, char * param, char * result, unsigned char valType);
void Log(char *filename, char *content);
int parseSystemForm(char* form, ipFormValues_t * result);
int parseCentralForm(char* form, isiFormValues_t * result);
int parseSupervisorForm(char* form, svFormValues_t * result);
int parseCredentialForm(char* form, credentialFormValues_t * result);
void changeIP(ipFormValues_t * networkParam);
void changeIsiConf(isiFormValues_t * networkParam);
void changeSV(svFormValues_t * networkParam);
int changeCredential(credentialFormValues_t * credentialParam);
void b64_encode(char *clrstr, char *b64dst);
void b64_decode(char *b64src, char *clrdst);
void fillPage(struct file_data *page, char *pageName);


/* Implementation */
int searchValIntoForm(char * form, char * param, char * result, unsigned char valType)
{
	char *strValue, tmpValue[64];
	unsigned int valueLen, i;	

	strValue = strstr(form,param);
	if(strValue!=NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;	
		for(i=0;strValue[i+strlen(param)]!='&';i++)
			tmpValue[i] = strValue[i+strlen(param)];
		tmpValue[i] = '\0';		
		if(valType == 0)						// is a string
		{
			if(result == NULL)					// not valid pointer
			{
				result = malloc(strlen(tmpValue));
			}
			strncpy(result,tmpValue,strlen(tmpValue));
			return strlen(tmpValue);
		}
		else
		{
			return atoi(tmpValue);
		}
	}

	return -2;									// not found
}

void Log(char *filename, char *content)
{
	FILE * fd;
	char filenames[2][512];
	int size;
	struct stat st;
	time_t current_time;
	struct tm * tm_now;	
	char c_time_string[64];

	sprintf(filenames[0],"%s.0",filename);
	sprintf(filenames[1],"%s.1",filename);
	stat(filenames[0], &st);
	size = st.st_size;

	if(size > 45000)  
	{    
	char cmd[512*2+4];
	sprintf(cmd, "mv %s %s", filenames[0], filenames[1]);
	system(cmd);
	}

	current_time = time(NULL);	
	tm_now = localtime(&current_time);
	strftime(c_time_string,sizeof(c_time_string),"%d/%m/%y-%X",tm_now);

	fd = fopen(filenames[0],"a+");
	fprintf(fd, "%s:%s", c_time_string, content);
	fclose(fd);
}

int parseSystemForm(char* form, ipFormValues_t * result)
{
	unsigned int i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	//printf("\nThere are %d Parameters\n",nParam);
	
	result->ip.addr1 = searchValIntoForm(form, "ip1=", NULL, INT_TYPE);
	result->ip.addr2 = searchValIntoForm(form, "ip2=", NULL, INT_TYPE);
	result->ip.addr3 = searchValIntoForm(form, "ip3=", NULL, INT_TYPE);
	result->ip.addr4 = searchValIntoForm(form, "ip4=", NULL, INT_TYPE);
	result->sn.addr1 = searchValIntoForm(form, "sn1=", NULL, INT_TYPE);
	result->sn.addr2 = searchValIntoForm(form, "sn2=", NULL, INT_TYPE);
	result->sn.addr3 = searchValIntoForm(form, "sn3=", NULL, INT_TYPE);
	result->sn.addr4 = searchValIntoForm(form, "sn4=", NULL, INT_TYPE);
	result->gw.addr1 = searchValIntoForm(form, "gw1=", NULL, INT_TYPE);
	result->gw.addr2 = searchValIntoForm(form, "gw2=", NULL, INT_TYPE);
	result->gw.addr3 = searchValIntoForm(form, "gw3=", NULL, INT_TYPE);
	result->gw.addr4 = searchValIntoForm(form, "gw4=", NULL, INT_TYPE);
	if(strstr(form,"dhcpChk=on"))
		result->dhcp = 1;
	else /*if(strstr(form,"dhcpChk=off"))*/		// static IP
		result->dhcp = 0;		


	char logString[256];
	sprintf(logString,"New network config:\nDHCP:%d\nIP:%d.%d.%d.%d\nSN:%d.%d.%d.%d\nGW:%d.%d.%d.%d\n",result->dhcp,
																		result->ip.addr1,result->ip.addr2,result->ip.addr3,result->ip.addr4,
																		result->sn.addr1,result->sn.addr2,result->sn.addr3,result->sn.addr4,
																		result->gw.addr1,result->gw.addr2,result->gw.addr3,result->gw.addr4);
	printf(logString);

    return nParam;   
}

int parseCentralForm(char* form, isiFormValues_t * result)
{
	unsigned int i, nParam=0;
	char tmpValue[64];
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;
	
	searchValIntoForm(form, "centralType=", result->centralType, STRING_TYPE);	
	searchValIntoForm(form, "centralModel=", result->centralModel, STRING_TYPE);

	if((strncmp(result->centralType,"notifier",strlen("notifier"))==0) || (strncmp(result->centralType,"honeywell",strlen("honeywell"))==0))			/* Consider only notifier params */
	{
		result->centralParam.address = searchValIntoForm(form, "notifierId=", NULL, INT_TYPE);
		result->centralParam.polling = searchValIntoForm(form, "notifierPolling=", NULL, INT_TYPE);
		searchValIntoForm(form, "notifierConnection=", result->centralParam.connection, STRING_TYPE);
		searchValIntoForm(form, "isiPort=", tmpValue, STRING_TYPE);
		if(strncmp(tmpValue,"com1",strlen("com1"))==0)
			result->centralParam.serialPort = 0;
		else if(strncmp(tmpValue,"com2",strlen("com2"))==0)
			result->centralParam.serialPort = 1;
		else if(strncmp(tmpValue,"usb1",strlen("usb1"))==0)
			result->centralParam.serialPort = 2;
		else if(strncmp(tmpValue,"usb2",strlen("usb2"))==0)
			result->centralParam.serialPort = 3;
		else if(strncmp(tmpValue,"usb3",strlen("usb3"))==0)
			result->centralParam.serialPort = 4;
		result->centralParam.ip.addr1 = searchValIntoForm(form, "notifierIP1=", NULL, INT_TYPE);
		result->centralParam.ip.addr2 = searchValIntoForm(form, "notifierIP2=", NULL, INT_TYPE);
		result->centralParam.ip.addr3 = searchValIntoForm(form, "notifierIP3=", NULL, INT_TYPE);
		result->centralParam.ip.addr4 = searchValIntoForm(form, "notifierIP4=", NULL, INT_TYPE);
		result->centralParam.networkPort = searchValIntoForm(form, "notifierPort=", NULL, INT_TYPE);	
		result->centralParam.baudrate = searchValIntoForm(form, "notifierBaudrate=", NULL, INT_TYPE);
		searchValIntoForm(form, "notifierNumeration=", tmpValue, STRING_TYPE);
		if(strncmp(tmpValue,"standard",strlen("standard"))==0)
			result->centralParam.numeration = 0;			
		else if(strncmp(tmpValue,"stdRiass",strlen("stdRiass"))==0)
			result->centralParam.numeration = 1;									
	}
	else if(strncmp(result->centralType,"tecnofire",strlen("tecnofire"))==0)	/* Consider only tecnofire params */
	{
		searchValIntoForm(form, "tecnofireCode=", result->centralParam.code, STRING_TYPE);
		result->centralParam.ip.addr1 = searchValIntoForm(form, "tecnofireIP1=", NULL, INT_TYPE);
		result->centralParam.ip.addr2 = searchValIntoForm(form, "tecnofireIP2=", NULL, INT_TYPE);
		result->centralParam.ip.addr3 = searchValIntoForm(form, "tecnofireIP3=", NULL, INT_TYPE);
		result->centralParam.ip.addr4 = searchValIntoForm(form, "tecnofireIP4=", NULL, INT_TYPE);
		result->centralParam.networkPort = searchValIntoForm(form, "tecnofirePort=", NULL, INT_TYPE);	
		searchValIntoForm(form, "tecnofirePass=", result->centralParam.passphrase, STRING_TYPE);
	}
	else if(strncmp(result->centralType,"def",strlen("def"))==0)				/* Consider only def params */
	{
		result->centralParam.plant = searchValIntoForm(form, "defPlant=", NULL, INT_TYPE);
		result->centralParam.address = searchValIntoForm(form, "defId=", NULL, INT_TYPE);
		result->centralParam.baudrate = searchValIntoForm(form, "defBaudrate=", NULL, INT_TYPE);
		result->centralParam.registerDimension = searchValIntoForm(form, "defMaxReg=", NULL, INT_TYPE);
		result->centralParam.polling = searchValIntoForm(form, "defPolling=", NULL, INT_TYPE);
	}
	else if(strncmp(result->centralType,"detfire",strlen("detfire"))==0)		/* Consider only detfire params */
	{
		result->centralParam.address = searchValIntoForm(form, "detfireAdd=", NULL, INT_TYPE);
		result->centralParam.baudrate = searchValIntoForm(form, "detfireBaudrate=", NULL, INT_TYPE);		
	}

	char logString[256];
	sprintf(logString,"%s:%s\n",result->centralType,result->centralModel);
	printf(logString);
	Log("/tmp/webserver.log",logString);
	sprintf(logString,"New central config:\n\tconnection:%s\n\tserialPort:%d\n\tplant:%d\n\taddress:%d\n\tbaudrate:%d\n\tIP:%d.%d.%d.%d\n\tnetworkPort:%d\n\tnumeration:%d\n\tcode:%s\n\tpassphrase:%s\n\tregisterDimension:%d\n\tpolling:%d\n",
																		result->centralParam.connection,
																		result->centralParam.serialPort,
																		result->centralParam.plant,
																		result->centralParam.address,
																		result->centralParam.baudrate,																		
																		result->centralParam.ip.addr1,result->centralParam.ip.addr2,result->centralParam.ip.addr3,result->centralParam.ip.addr4,
																		result->centralParam.networkPort,
																		result->centralParam.numeration,
																		result->centralParam.code,
																		result->centralParam.passphrase,
																		result->centralParam.registerDimension,
																		result->centralParam.polling);
	printf(logString);
	Log("/tmp/webserver.log",logString);

    return nParam;   
}

int parseSupervisorForm(char* form, svFormValues_t * result)
{
	unsigned int i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	printf("\nThere are %d Parameters\n",nParam);	

    return nParam;   
}

int parseCredentialForm(char* form, credentialFormValues_t * result)
{
	unsigned int i, nParam=0;
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	//printf("\nThere are %d Parameters\n",nParam);
	
	searchValIntoForm(form, "oldPwd=", result->oldPassword, STRING_TYPE);
	searchValIntoForm(form, "newPwd=", result->oldPassword, STRING_TYPE);
	searchValIntoForm(form, "newPwd2=", result->oldPassword, STRING_TYPE);
	searchValIntoForm(form, "user=", result->oldPassword, STRING_TYPE);

	printf("Ho finito di parsificare le credenziali\n");
    return nParam;   
}

void changeIP(ipFormValues_t * networkParam)
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

void changeIsiConf(isiFormValues_t * isiParam)
{

}

void changeSV(svFormValues_t * svParam)
{

}

int changeCredential(credentialFormValues_t * credentialParam)
{
	unsigned int i;
	int returnVal = 0;
	FILE *fd = fopen("serverroot/pwd","r");
	char tmpString[256], username[64], password[64], index;
	
	fgets(tmpString,sizeof(tmpString),fd);
	fclose(fd);

	for(i=0;tmpString[i]!=':' && i<sizeof(username);i++)
		username[i] = tmpString[i];	
	username[i++] = '\0';
	index = i;
	while(tmpString[i]!='\n' && i<sizeof(username))
	{
		password[i-index] = tmpString[i];
		i++;
	}
	password[i-index] = '\0';

	if( (strcmp(credentialParam->username,username)==0)&&
		(strcmp(credentialParam->oldPassword,password)==0)&&
		(strcmp(credentialParam->newPassword,credentialParam->newPassword2)==0))
	{		
		printf("Sto cambiando credenziali\n");
		fd = fopen("serverroot/pwd","w");
		fprintf(fd,"%s:%s\n", username, credentialParam->newPassword);
		fclose(fd);
		returnVal = 1;
	}

	free(credentialParam->username);
	free(credentialParam->oldPassword);
	free(credentialParam->newPassword);
	free(credentialParam->newPassword2);

	return returnVal;
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

/* fill html page when the resource is requested by a host */
void fillPage(struct file_data *page, char *pageName)
{
	FILE * fd;
	char tmpString[100], *pageFilled, *pageCpy, *pageRow, addressString[22], paramFound=0;
	unsigned int networkParams[13];
	unsigned int idx=0, newPageIndex=0, i, old_pageRowIdx;
	int pageRowIdx;
	char networkParamList[13][7+1];

	strcpy(networkParamList[0],"dhcpChk");
	strcpy(networkParamList[1],"ip1");
	strcpy(networkParamList[2],"ip2");
	strcpy(networkParamList[3],"ip3");
	strcpy(networkParamList[4],"ip4");
	strcpy(networkParamList[5],"sn1");
	strcpy(networkParamList[6],"sn2");
	strcpy(networkParamList[7],"sn3");
	strcpy(networkParamList[8],"sn4");
	strcpy(networkParamList[9],"gw1");
	strcpy(networkParamList[10],"gw2");
	strcpy(networkParamList[11],"gw3");
	strcpy(networkParamList[12],"gw4");

	pageCpy = (char *)malloc(page->size);
	memcpy(pageCpy,page->data,page->size);
	pageFilled = malloc(page->size + N_BYTES_PARAMS);
	printf("Page size:%d\n",page->size);

	if(strncmp(pageName,"/parametri_di_centrale.html",strlen("parametri_di_centrale"))==0)
	{

	}
	else if(strncmp(pageName,"/parametri_di_sistema.html",strlen("parametri_di_sistema"))==0)
	{
		/* show network configuration */
		fd = fopen("/etc/network/network.conf", "r");
		while(fgets(tmpString,100,fd))
		{	
			if(strncmp(tmpString,DHCP_OPTIONS,strlen(DHCP_OPTIONS))==0)
			{			
				if(strstr(tmpString,"dhcp")!=NULL)
				{
					networkParams[0] = 1;
				}
				else
				{
					networkParams[0] = 0;
				}
			}
			else if(strncmp(tmpString,IP_STRING,strlen(IP_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[1] = atoi(strtok(NULL,"."));
				networkParams[2] = atoi(strtok(NULL,"."));
				networkParams[3] = atoi(strtok(NULL,"."));
				networkParams[4] = atoi(strtok(NULL,"\""));
			}
			else if(strncmp(tmpString,SUBNET_STRING,strlen(SUBNET_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[5] = atoi(strtok(NULL,"."));
				networkParams[6] = atoi(strtok(NULL,"."));
				networkParams[7] = atoi(strtok(NULL,"."));
				networkParams[8] = atoi(strtok(NULL,"\""));	
			}
			else if(strncmp(tmpString,GATEWAY_STRING,strlen(GATEWAY_STRING))==0)
			{
				strtok(tmpString,"\"");
				networkParams[9] = atoi(strtok(NULL,"."));
				networkParams[10] = atoi(strtok(NULL,"."));
				networkParams[11] = atoi(strtok(NULL,"."));
				networkParams[12] = atoi(strtok(NULL,"\""));
			}
		}
		fclose(fd);

		sprintf(tmpString,"DHCP:%d\tIP:%d.%d.%d.%d\tSN:%d.%d.%d.%d\tGW:%d.%d.%d.%d\n",networkParams[0],
																					  networkParams[1], networkParams[2], networkParams[3], networkParams[4],
																					  networkParams[5], networkParams[6], networkParams[7], networkParams[8],
																					  networkParams[9], networkParams[10], networkParams[11], networkParams[12]);
		Log("/tmp/webserver.log",tmpString);

		pageRowIdx=0;
		old_pageRowIdx=0;
		while(pageRowIdx<page->size)
		{			
			while(pageRowIdx<page->size && ((((char*)(page->data))[pageRowIdx])!='\n'))		// search next new line
				pageRowIdx++;
			if(pageRowIdx<page->size)														// new line found
			{				
				pageRow = malloc(pageRowIdx - old_pageRowIdx + 2);				
				memcpy(pageRow,page->data+old_pageRowIdx,pageRowIdx - old_pageRowIdx + 1);				
				memcpy(pageFilled+newPageIndex,pageRow,pageRowIdx - old_pageRowIdx + 1);				
				pageRow[pageRowIdx - old_pageRowIdx] = '\0';								// add terminator	

				i=0;
				while(i<13 && !paramFound)												// search network parameter rows 
				{					
					if(strstr(pageRow,networkParamList[i])!=NULL)
						paramFound = 1;					
					else
						i++;
				}
				if(paramFound)
				{
					paramFound = 0;
					for(idx=0;idx<strlen(pageRow) && (pageRow[idx]!='>');idx++)			// search end of input field
						;
					if(idx<strlen(pageRow))												// end of input field found
					{
						if(i!=0){
							sprintf(addressString," value=\"%d\">\n",networkParams[i]);					
							strncpy(pageFilled+newPageIndex+idx,addressString,strlen(addressString));							
							newPageIndex += idx+strlen(addressString);																
						}
						else															// dhcp
						{							
							if(networkParams[0] == 0)									// dhcp off
								sprintf(addressString," value=\"off\">\n");					
							else														// dhcp on
								sprintf(addressString," value=\"on\" checked>\n");					
							strncpy(pageFilled+newPageIndex+idx,addressString,strlen(addressString));
							newPageIndex += idx+strlen(addressString);												
						}		
					}
					else																// error, go on without changing the row
					{
						newPageIndex += pageRowIdx - old_pageRowIdx + 1;		
					}
				}
				else
				{					
						newPageIndex += pageRowIdx - old_pageRowIdx + 1;					
				}
				if(pageRow != NULL)	
					free(pageRow);

				old_pageRowIdx = ++pageRowIdx;
			}
		}
		*(pageFilled+newPageIndex) = '\0';
		free(page->data);
		page->data = malloc(strlen(pageFilled));
		memcpy((char *)(page->data),pageFilled,strlen(pageFilled));
		page->size = strlen(pageFilled);	
	}
	else if(strncmp(pageName,"/parametri_di_supervisione.html",strlen("parametri_di_supervisione"))==0)
	{

	}

	if(pageFilled != NULL)
		free(pageFilled);
	if(pageCpy != NULL)
		free(pageCpy);
}
/* */
