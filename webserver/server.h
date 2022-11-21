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

#define ON 					1
#define OFF					0
#define INPUT 				1
#define BYPASS 				0
#define PULSE				1
#define CONTINUOUS 			0

#define SELECT				0
#define INPUT				1
#define CHECKBOX			2

#define ALARM 				0
#define DIAGNOSTIC 			1
#define ALARM_DIAGNOSTIC 	2

#define TYPE_CONTINUOUS		0
#define TYPE_FOLLOW_STATE	1

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
	char id[64];					/* for Detfire only */
	unsigned int registerDimension;	/* for DEF only */
	unsigned int polling;
	unsigned char inputBalance;		/* for local only */
}centralParam_t;

typedef struct{
	unsigned char function;			
	char description[64];
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
	char description[64];
	char number[32];
	char sms;
	char voice;
	char alertType;
	char cmd;
}phone_t;

typedef struct{
	char plantLabel[64];
	char hiCloudEn;
	unsigned int hiCloudPlantId;	
	char hiCloudRegister[64];
	char cidEn;
	char cidRegister1[64];
	char cidRegister2[64];
	char pinSim[64];
	char apnSim[64];
	char userSim[64];
	char pwdSim[64];
	phone_t phone[8];
}svFormValues_t;

typedef struct{
	char username[64];
	char oldPassword[64];
	char newPassword[64];
	char newPassword2[64];
}credentialFormValues_t;

typedef struct{
	char description[64];
	char condition;
	char normalState;
	char duration;
	char type;
}outputValues_t;

typedef struct{
	outputValues_t out[5];
}outFormValues_t;


/* Index */
int searchValIntoForm(char * form, char * param, char * result, unsigned char valType);
void Log(char *filename, char *content);

int parseSystemForm(char* form, ipFormValues_t * result);
int parseCentralForm(char* form, isiFormValues_t * result);
int parseSupervisorForm(char* form, svFormValues_t * result);
int parseCredentialForm(char* form, credentialFormValues_t * result);
int parseOutputForm(char* form, outFormValues_t * result);

void changeIP(ipFormValues_t * networkParam);
void changeIsiConf(isiFormValues_t * networkParam);
void changeSV(svFormValues_t * networkParam);
int  changeCredential(credentialFormValues_t * credentialParam);
void changeOut(outFormValues_t * credentialParam);

void b64_encode(char *clrstr, char *b64dst);
void b64_decode(char *b64src, char *clrdst);
void fillPage(struct file_data *page, char *pageName);


/* Implementation */
unsigned char changeValInHtmlPage(char *pageRow, char *param, char *value, char * pageFilled, unsigned int *newPageIndex, unsigned char inputType)
{
	unsigned int idx,i;
	char *tmpString, paramStr[64], valString[256], tmpValue[64];

	switch(inputType)
	{
		case SELECT:
			sprintf(paramStr," value=\"%s\">",value);			
			break;
		case CHECKBOX:
		case INPUT:
			sprintf(paramStr,"id=\"%s\"",param);
			break;		
	}	
	tmpString = strstr(pageRow,paramStr);

	if(tmpString != NULL)
	{		
		for(idx=0;idx<strlen(pageRow) && (pageRow[idx]!='>');idx++)			// search end of input field
			valString[idx]=pageRow[idx];
		valString[idx] = '\0';
		if(idx<strlen(pageRow))												// end of input field found
		{						
				switch(inputType)
				{
					case SELECT:
						strcat(valString," selected");	
						break;
					case INPUT:
						sprintf(tmpValue," value=\"%s\"",value);
						strcat(valString,tmpValue);
						break;
					case CHECKBOX:
						if(strcmp(value,"on")==0)
							strcat(valString," checked");						
						break;
				}	
				for(i=strlen(valString);idx<strlen(pageRow) && (pageRow[idx]!='\n');i++,idx++){
					valString[i] = pageRow[idx];
				}						
				valString[i] = '\0';
				strncpy(pageFilled+(*newPageIndex),valString,strlen(valString));											
				(*newPageIndex) = (*newPageIndex)+strlen(valString);					
				return 0;
		}
		else																// error, go on without changing the row									
			return 1;		
	}
	else			
			return 1;		
}

int extractValFromJson(char * json, char * searchStr, char * result, int type)
{
	char *searchValStr, param[64], tmpString[64];
	unsigned int i,j;

	sprintf(param,"\"%s\":",searchStr);
	searchValStr = strstr(json,param);
	for(i=0;(i<strlen(searchValStr)&&(searchValStr[i]!=':'));i++)
		;
	if(i<strlen(searchValStr))
	{
		i++;
		if(searchValStr[i]=='"')			// the value searched is a string
			i++;		
		j=0;		
		while((i<strlen(searchValStr))&&(searchValStr[i]!='"')&&(searchValStr[i]!=',')&&(searchValStr[i]!='}'))
		{
			if(type == STRING_TYPE)		
				result[j++] = searchValStr[i++];
			else
				tmpString[j++] = searchValStr[i++];		
		}
		if(type == STRING_TYPE)
		{
			result[j] = '\0';		
			return 0;
		}
		else
		{
			tmpString[j] = '\0';
			return atoi(tmpString);
		}		
	}
	else
		return -1;
}

int searchValIntoForm(char * form, char * param, char * result, unsigned char valType)
{
	char *strValue, tmpValue[64];
	unsigned int valueLen, i;	

	strValue = strstr(form,param);
	if(strValue!=NULL)
	{
		for(valueLen=0;(valueLen<strlen(strValue))&&(strValue[valueLen]!='&');valueLen++)
			;			
		for(i=0;(strValue[i+strlen(param)]!='&') && (i<valueLen);i++)
			tmpValue[i] = strValue[i+strlen(param)];
		tmpValue[i] = '\0';				
		if(valType == 0)						// is a string
		{						
			strncpy(result,tmpValue,strlen(tmpValue));		
			result[strlen(tmpValue)] = '\0';			
			return strlen(result);
		}
		else
		{
			return atoi(tmpValue);
		}
	}

	return -1;									// not found
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
	char tmpValue[64], formValStr[64];
	
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
		searchValIntoForm(form, "detfireConnection=", result->centralParam.connection, STRING_TYPE);
		searchValIntoForm(form, "detfireIsiPort=", tmpValue, STRING_TYPE);
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
		searchValIntoForm(form, "detfireAdd=", result->centralParam.id, STRING_TYPE);
		result->centralParam.baudrate = searchValIntoForm(form, "detfireBaudrate=", NULL, INT_TYPE);		
	}
	else if(strncmp(result->centralType,"local",strlen("local"))==0)			/* Consider only local params */
	{
		searchValIntoForm(form, "balanceType=", tmpValue, STRING_TYPE);		
		if(strncmp(tmpValue,"onOffNA",strlen("onOffNA"))==0)
			result->centralParam.inputBalance = 2;
		else if(strncmp(tmpValue,"onOffNC",strlen("onOffNC"))==0)
			result->centralParam.inputBalance = 3;
		else if(strncmp(tmpValue,"triple",strlen("triple"))==0)
			result->centralParam.inputBalance = 1;
		for(i=0;i<8;i++)
		{
			sprintf(tmpValue,"in%dFunction=",i+1);
			searchValIntoForm(form, tmpValue, formValStr, STRING_TYPE);
			if(strcmp(formValStr,"alarm")==0)
				result->inputs[i].function = COND_ALARM;
			else if(strcmp(formValStr,"broken")==0)
				result->inputs[i].function = COND_FAIL;
			else if(strcmp(formValStr,"exclusion")==0)
				result->inputs[i].function = COND_EXCL;
			else if(strcmp(formValStr,"bypass")==0)
				result->inputs[i].function = COND_BYPASS;			
			sprintf(tmpValue,"in%dDesc=",i+1);
			searchValIntoForm(form, tmpValue, result->inputs[i].description, STRING_TYPE);
			sprintf(tmpValue,"in%denable24h=",i+1);
			searchValIntoForm(form, tmpValue, tmpValue, STRING_TYPE);
			if(strcmp(tmpValue,"on")==0)
				result->inputs[i].allDayActive = ON;
			else
				result->inputs[i].allDayActive = OFF;
			sprintf(tmpValue,"in%dDelay=",i+1);
			result->inputs[i].delay = searchValIntoForm(form, tmpValue, NULL, INT_TYPE);
			sprintf(tmpValue,"in%dDelayType=",i+1);
			searchValIntoForm(form, tmpValue, tmpValue, STRING_TYPE);			
			if(strcmp(tmpValue,"pulse")==0)
				result->inputs[i].delayType = PULSE;
			else
				result->inputs[i].delayType = CONTINUOUS;
			sprintf(tmpValue,"in%dRestore=",i+1);
			searchValIntoForm(form, tmpValue, tmpValue, STRING_TYPE);
			if(strcmp(tmpValue,"on")==0)			
				result->inputs[i].restore = ON;
			else
				result->inputs[i].restore = OFF;
			sprintf(tmpValue,"in%dRestoreCondition=",i+1);
			searchValIntoForm(form, tmpValue, tmpValue, STRING_TYPE);
			if(strcmp(tmpValue,"input")==0)			
				result->inputs[i].restoreCondition = INPUT;
			else
				result->inputs[i].restoreCondition = BYPASS;	
		}		
	}	

    return nParam;   
}

int parseSupervisorForm(char* form, svFormValues_t * result)
{
	unsigned int i, nParam=0;
	char tmpString[64], tmpValue[64];

	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	//printf("\nThere are %d Parameters\n",nParam);

	searchValIntoForm(form, "plantLabel=", result->plantLabel, STRING_TYPE);
	sprintf(tmpString,"enableHiCloud=");
	searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
	printf("Il valore di hiCloudEn sarà:%s\n",tmpValue);
	if(strncmp(tmpValue,"on",strlen("on"))==0)
		result->hiCloudEn = ON;
	else
		result->hiCloudEn = OFF;
	printf("hiCloudEn:%d\n",result->hiCloudEn);
	result->hiCloudPlantId = searchValIntoForm(form, "plantId=", NULL, INT_TYPE);
	searchValIntoForm(form, "urlRegister=", result->hiCloudRegister, STRING_TYPE);
	sprintf(tmpString,"enableCid=");
	searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
	if(strncmp(tmpValue,"on",strlen("on"))==0)
		result->cidEn = ON;
	else
		result->cidEn = OFF;
	searchValIntoForm(form, "urlCid1=", result->cidRegister1, STRING_TYPE);
	searchValIntoForm(form, "urlCid2=", result->cidRegister2, STRING_TYPE);
	searchValIntoForm(form, "pin=", result->pinSim, STRING_TYPE);
	searchValIntoForm(form, "apn=", result->apnSim, STRING_TYPE);
	searchValIntoForm(form, "user=", result->userSim, STRING_TYPE);
	searchValIntoForm(form, "pwd=", result->pwdSim, STRING_TYPE);
	
	for(i=0;i<8;i++)
	{
		sprintf(tmpString,"descCell%d=",i+1);
		searchValIntoForm(form, tmpString, result->phone[i].description, STRING_TYPE);
		sprintf(tmpString,"cell%d=",i+1);
		searchValIntoForm(form, tmpString, result->phone[i].number, STRING_TYPE);
		sprintf(tmpString,"mexCell%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
		if(strncmp(tmpValue,"on",strlen("on"))==0)
			result->phone[i].sms = ON;
		else
			result->phone[i].sms = OFF;
		sprintf(tmpString,"voiceCell%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
		if(strncmp(tmpValue,"on",strlen("on"))==0)
			result->phone[i].voice = ON;
		else
			result->phone[i].voice = OFF;
		sprintf(tmpString,"alarmCell%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
		if(strcmp(tmpValue,"alarm")==0)
			result->phone[i].alertType = ALARM;
		else if(strcmp(tmpValue,"diagnostic")==0)
			result->phone[i].alertType = DIAGNOSTIC;
		else if(strcmp(tmpValue,"alarm_diagnostic")==0)
			result->phone[i].alertType = ALARM_DIAGNOSTIC;	
		sprintf(tmpString,"cmdCell%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);
		if(strncmp(tmpValue,"on",strlen("on"))==0)
			result->phone[i].cmd = ON;
		else
			result->phone[i].cmd = OFF;	
	}

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
	
	printf("Form:%s\n",form);

	searchValIntoForm(form, "oldPwd=", result->oldPassword, STRING_TYPE);
	searchValIntoForm(form, "newPwd=", result->newPassword, STRING_TYPE);
	searchValIntoForm(form, "newPwd2=", result->newPassword2, STRING_TYPE);
	searchValIntoForm(form, "user=", result->username, STRING_TYPE);

	printf("PARSING\nUser:%s\nPwd:%s\nPwd2:%s\noldPwd:%s\n",result->username,result->newPassword,result->newPassword2,result->oldPassword);


	printf("Ho finito di parsificare le credenziali\n");
    return nParam;   
}

int parseOutputForm(char* form, outFormValues_t * result)
{
	unsigned int i, nParam=0;
	char tmpString[64], tmpValue[64];
	
	for(i=0; i<strlen(form);i++)
	{
		if(form[i]=='&')
			nParam++;
	}
	if(nParam)
		nParam++;

	//printf("\nThere are %d Parameters\n",nParam);
	
	for(i=0;i<5;i++)
	{
		sprintf(tmpString,"descOut%d=",i+1);
		searchValIntoForm(form, tmpString, result->out[i].description, STRING_TYPE);	
		sprintf(tmpString,"conditionOut%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);	
		if(strcmp(tmpValue,"alarm")==0)
			result->out[i].condition = COND_ALARM;
		else if(strcmp(tmpValue,"broken")==0)
			result->out[i].condition = COND_FAIL;
		else if(strcmp(tmpValue,"exclusion")==0)
			result->out[i].condition = COND_EXCL;
		else if(strcmp(tmpValue,"bypass")==0)
			result->out[i].condition = COND_BYPASS;
		else if(strcmp(tmpValue,"diagnostic")==0)
			result->out[i].condition = COND_REMOTE;
		sprintf(tmpString,"normalStateOut%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);	
		if(strcmp(tmpValue,"off")==0)
			result->out[i].normalState = OFF;
		else
			result->out[i].normalState = ON;		 
		sprintf(tmpString,"durationOut%d=",i+1);
		result->out[i].duration = searchValIntoForm(form, tmpString, NULL, INT_TYPE);	
		sprintf(tmpString,"typeOut%d=",i+1);
		searchValIntoForm(form, tmpString, tmpValue, STRING_TYPE);	
		if(strcmp(tmpValue,"followState")==0)
			result->out[i].type = TYPE_FOLLOW_STATE;
		else
			result->out[i].type = TYPE_CONTINUOUS;		 
	}

	printf("Ho finito di parsificare le uscite\n");
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
			for(i=0;i<index-1;i++)
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
	char tmpString[4096], newString[4096], isiconf[1024];
	unsigned char centralModel=0;
	unsigned int i,j;
	FILE *fd, *fd_new;

	fd = fopen("std_isi.conf","r");

	isiconf[0] = '\0';											// to be sure that consecutive calls use an empty string on strcat

	while(fgets(tmpString,sizeof(tmpString),fd) != NULL)		// load standard isi.conf 
		strcat(isiconf,tmpString);
	fclose(fd);

	/* Update isi.conf */
	//fd = fopen("/isi/isi.conf","w+");
	fd = fopen("/home/utente/isi.conf","w+");
	fprintf(fd,isiconf);

	if(strcmp(isiParam->centralType,"local")==0)				
	{
		sprintf(tmpString,"Balance=%d\n\n",isiParam->centralParam.inputBalance);		
		fprintf(fd,tmpString);
	}
	else
	{
		sprintf(tmpString,"\n# Centrale %s\n[2]\n",isiParam->centralType);		
		fprintf(fd,tmpString);

		if((strcmp(isiParam->centralType,"notifier")==0) || (strcmp(isiParam->centralType,"honeywell")==0))
		{			
			if(strcmp(isiParam->centralParam.connection,"lan")==0)
			{
				fprintf(fd,"Protocol=MODBUS-NOTIFIER\nId=%d\nAddress=%d.%d.%d.%d\nPort=%d\n", 	isiParam->centralParam.address,
																					  			isiParam->centralParam.ip.addr1, isiParam->centralParam.ip.addr2, isiParam->centralParam.ip.addr3, isiParam->centralParam.ip.addr4, 
																					  			isiParam->centralParam.networkPort);				
			}
			else if(strcmp(isiParam->centralParam.connection,"com")==0)
			{
				fprintf(fd,"Protocol=CEI\nId=%d\nPort=/dev/ttyS%d\nBaud=%d\nPolling=%d\n", 	isiParam->centralParam.address,																			  
																			   				isiParam->centralParam.serialPort,
																			   				isiParam->centralParam.baudrate,
																			   				isiParam->centralParam.polling);	
			}
		}
		else if(strcmp(isiParam->centralType,"tecnofire")==0)
		{
			if(strcmp(isiParam->centralModel,"TFA1-298")==0)
				centralModel = 1;
			else if(strcmp(isiParam->centralModel,"TFA1-596")==0)
				centralModel = 2;
			else if(strcmp(isiParam->centralModel,"TFA1-1192")==0)
				centralModel = 3;
			fprintf(fd,"Protocol=TECNOOUT\nType=%d\nCode=%s\nAddr=%d.%d.%d.%d:%d\nPassphrase=%s\n", centralModel,
																									isiParam->centralParam.code,
																						  			isiParam->centralParam.ip.addr1, isiParam->centralParam.ip.addr2, isiParam->centralParam.ip.addr3, isiParam->centralParam.ip.addr4, isiParam->centralParam.networkPort,
																						  			isiParam->centralParam.passphrase);
		}
		else if(strcmp(isiParam->centralType,"def")==0)
		{
			fprintf(fd,"Protocol=MODBUS-DEF\nImp=%d\nId=%d\nPort=/dev/ttyS%d\nBaud=%d\n", isiParam->centralParam.plant,
																						  isiParam->centralParam.address,
																						  isiParam->centralParam.serialPort,
																						  isiParam->centralParam.baudrate);
		}
		else if(strcmp(isiParam->centralType,"detfire")==0)
		{
			fprintf(fd,"Protocol=MAY2\nId=%s\nPort=/dev/ttyS%d\nBaud=%d\n", isiParam->centralParam.id,
																			isiParam->centralParam.serialPort,
																			isiParam->centralParam.baudrate);
		}
	}

	fclose(fd);

	/* Save values into file */
	fd = fopen("webserver.sav","r");
	fd_new = fopen("webserver.sav.new","w+");
	while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
	{
		if(strstr(tmpString,"\"central\":{")!=NULL)
		{
			for(i=0;i<strlen(tmpString)&&(strncmp(&(tmpString[i]),"\"central\":{",strlen("\"central\":{"))!=0);i++)
				;		
			strncpy(newString,tmpString,i+strlen("\"central\":{"));			// copy first part
			newString[i+strlen("\"central\":{")] = '\0';					// add terminator					
			sprintf(newString,"%s\"type\":\"%s\",",						newString,isiParam->centralType);
			sprintf(newString,"%s\"model\":\"%s\",",					newString,isiParam->centralModel);
			sprintf(newString,"%s\"connection\":\"%s\",",				newString,isiParam->centralParam.connection);
			sprintf(newString,"%s\"serialPort\":%d,",					newString,isiParam->centralParam.serialPort);
			sprintf(newString,"%s\"plant\":%d,",						newString,isiParam->centralParam.plant);
			sprintf(newString,"%s\"address\":%d,",						newString,isiParam->centralParam.address);
			sprintf(newString,"%s\"baudrate\":%d,",						newString,isiParam->centralParam.baudrate);
			sprintf(newString,"%s\"ip\":\"%d.%d.%d.%d\",",				newString,isiParam->centralParam.ip.addr1,isiParam->centralParam.ip.addr2,isiParam->centralParam.ip.addr3,isiParam->centralParam.ip.addr4);
			sprintf(newString,"%s\"networkPort\":%d,",					newString,isiParam->centralParam.networkPort);
			sprintf(newString,"%s\"numeration\":%d,",					newString,isiParam->centralParam.numeration);	
			sprintf(newString,"%s\"code\":\"%s\",",						newString,isiParam->centralParam.code);
			sprintf(newString,"%s\"passphrase\":\"%s\",",				newString,isiParam->centralParam.passphrase);
			sprintf(newString,"%s\"id\":\"%s\",",						newString,isiParam->centralParam.id);
			sprintf(newString,"%s\"registerDimension\":%d,",			newString,isiParam->centralParam.registerDimension);
			sprintf(newString,"%s\"polling\":%d,",						newString,isiParam->centralParam.polling);
			sprintf(newString,"%s\"inputBalance\":%d},\"in\":[",		newString,isiParam->centralParam.inputBalance);	
			for(j=0;j<8;j++)
			{
				sprintf(newString,"%s{\"idx\":%d,",						newString,j);	
				sprintf(newString,"%s\"tipo\":%d,",						newString,isiParam->inputs[j].function);
				sprintf(newString,"%s\"h24\":%d,",						newString,isiParam->inputs[j].allDayActive);	
				sprintf(newString,"%s\"ritardo\":%d,",					newString,isiParam->inputs[j].delay);
				sprintf(newString,"%s\"tipo_rit\":%d,",					newString,isiParam->inputs[j].delayType);
				sprintf(newString,"%s\"ripristino\":%d,",				newString,isiParam->inputs[j].restore);	
				sprintf(newString,"%s\"descr\":\"%s\",",				newString,isiParam->inputs[j].description);																
				if(j==7)
					sprintf(newString,"%s\"cond\":%d}",					newString,isiParam->inputs[j].restoreCondition);
				else
					sprintf(newString,"%s\"cond\":%d},",				newString,isiParam->inputs[j].restoreCondition);
			}

			
			while(tmpString[i]!=']' && i<strlen(tmpString))					// search end of param in original string
				i++;			

			for(j=strlen(newString);i<strlen(tmpString);i++,j++)			// copy final part
				newString[j] = tmpString[i];
			newString[j] = '\0';			
			//printf(tmpString);
			//Log("/tmp/webserver.log",tmpString);
		}
		fprintf(fd_new,newString);
	}
	fclose(fd);
	fclose(fd_new);
	system("mv webserver.sav.new webserver.sav");

	system("killall -9 isi");
}

void changeSV(svFormValues_t * svParam)
{
	char tmpString[4096], newString[4096];
	unsigned int i,j;
	FILE *fd, *fd_new;

	/* Save values into file */
	fd = fopen("webserver.sav","r");
	fd_new = fopen("webserver.sav.new","w+");
	while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
	{
		if(strstr(tmpString,"\"sv\":{")!=NULL)
		{
			for(i=0;i<strlen(tmpString)&&(strncmp(&(tmpString[i]),"\"sv\":{",strlen("\"sv\":{"))!=0);i++)
				;		
			strncpy(newString,tmpString,i+strlen("\"sv\":{"));			// copy first part
			newString[i+strlen("\"sv\":{")] = '\0';						// add terminator
			sprintf(newString,"%s\"descr\":\"%s\",",								newString,svParam->plantLabel);
			sprintf(newString,"%s\"hiCloud\":%d,",								newString,svParam->hiCloudEn);
			sprintf(newString,"%s\"hiCloudId\":%d,",							newString,svParam->hiCloudPlantId);
			sprintf(newString,"%s\"url\":\"%s\",",								newString,svParam->hiCloudRegister);			
			sprintf(newString,"%s\"cid\":%d,",									newString,svParam->cidEn);
			sprintf(newString,"%s\"cidReg1\":\"%s\",",								newString,svParam->cidRegister1);
			sprintf(newString,"%s\"cidReg2\":\"%s\",",								newString,svParam->cidRegister2);
			sprintf(newString,"%s\"pin\":\"%s\",",									newString,svParam->pinSim);
			sprintf(newString,"%s\"apn\":\"%s\",",									newString,svParam->apnSim);
			sprintf(newString,"%s\"user\":\"%s\",",									newString,svParam->userSim);
			sprintf(newString,"%s\"pwd\":\"%s\",\"phone\":[",					newString,svParam->pwdSim);
			for(j=0;j<8;j++)
			{
				sprintf(newString,"%s{\"idx\":%d,",							newString,j);	
				sprintf(newString,"%s\"sms\":%d,",							newString,svParam->phone[j].sms);	
				sprintf(newString,"%s\"voce\":%d,",							newString,svParam->phone[j].voice);	
				sprintf(newString,"%s\"tipo\":%d,",							newString,svParam->phone[j].alertType);
				sprintf(newString,"%s\"num\":\"%s\",",						newString,svParam->phone[j].number);					
				sprintf(newString,"%s\"cmd\":\"%d\",",						newString,svParam->phone[j].cmd);
				if(j==7)
					sprintf(newString,"%s\"descr\":\"%s\"}",					newString,svParam->phone[j].description);									
				else
					sprintf(newString,"%s\"descr\":\"%s\"},",				newString,svParam->phone[j].description);						
			}
			while(tmpString[i]!=']' && i<strlen(tmpString))					// search end of param in original string
				i++;			
			for(j=strlen(newString);i<strlen(tmpString);i++,j++)			// copy final part
				newString[j] = tmpString[i];
			newString[j] = '\0';
		}
		fprintf(fd_new,newString);
	}
	fclose(fd);
	fclose(fd_new);
	system("mv webserver.sav.new webserver.sav");

	/* change isi.conf */
	fd = fopen("isi.conf","r");
	fd_new = fopen("isi.conf.new","w+");
	while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
	{
		if(strstr(tmpString,"Protocol=MODEM")!=NULL)						// change modem configuration
		{
			fprintf(fd,"PIN=%s",svParam->pinSim);
			fprintf(fd,"APN=%s",svParam->apnSim);
			fprintf(fd,"User=%s",svParam->userSim);
			fprintf(fd,"Password=%s",svParam->pwdSim);
			i=0;
			for(j=0;j<8;j++)
			{
				if(svParam->phone[j].cmd == 1)
				{
					fprintf(fd_new,"PhoneNum%02d=%s",i,svParam->phone[j].number);
					i++;
				}
			}
		}
		else
			fprintf(fd_new,tmpString);		
	}
	fclose(fd);
	fclose(fd_new);
	system("mv isi.conf.new isi.conf");
	system("killall -9 isi");
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

	printf("User:%s\nPwd:%s\nPwd2:%s\noldPwd:%s\n",credentialParam->username,credentialParam->newPassword,credentialParam->newPassword2,credentialParam->oldPassword);

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

	return returnVal;
}

void changeOut(outFormValues_t * outParam)
{
	char tmpString[4096], newString[4096];
	unsigned int i,j;
	FILE *fd, *fd_new;

	/* Save values into file */
	fd = fopen("webserver.sav","r");
	fd_new = fopen("webserver.sav.new","w+");
	while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
	{
		if(strstr(tmpString,"\"out\":[")!=NULL)
		{
			for(i=0;i<strlen(tmpString)&&(strncmp(&(tmpString[i]),"\"out\":[",strlen("\"out\":["))!=0);i++)
				;		
			strncpy(newString,tmpString,i+strlen("\"out\":["));			// copy first part
			newString[i+strlen("\"out\":[")] = '\0';						// add terminator
			for(j=0;j<5;j++)
			{
				sprintf(newString,"%s{\"idx\":%d,",					newString,j);	
				sprintf(newString,"%s\"cond\":%d,",					newString,outParam->out[j].condition);	
				sprintf(newString,"%s\"na_nc\":%d,",				newString,outParam->out[j].normalState);												
				sprintf(newString,"%s\"durata\":%d,",				newString,outParam->out[j].duration);	
				sprintf(newString,"%s\"tipo\":%d,",					newString,outParam->out[j].type);
				if(j==4)					
					sprintf(newString,"%s\"descr\":\"%s\"}",			newString,outParam->out[j].description);
				else
					sprintf(newString,"%s\"descr\":\"%s\"},",			newString,outParam->out[j].description);
			}
			while(tmpString[i]!=']' && i<strlen(tmpString))				// search end of param in original string
				i++;			
			for(j=strlen(newString);i<strlen(tmpString);i++,j++)		// copy final part
				newString[j] = tmpString[i];
			newString[j] = '\0';
		}
		fprintf(fd_new,newString);
	}
	fclose(fd);
	fclose(fd_new);
	system("mv webserver.sav.new webserver.sav");	
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
	char tmpString[4096], *pageFilled, *pageRow, addressString[22], paramFound=0, valStr[64], *tmpPointer;
	unsigned int networkParams[13];
	unsigned int idx=0, newPageIndex=0, i, j, old_pageRowIdx;
	unsigned char changeRes, flagFound[8][6];
	int pageRowIdx;
	char networkParamList[13][7+1];	
	isiFormValues_t central;
	outputValues_t output[5];
	svFormValues_t sv;

	for(i=0;i<8;i++)
		for(j=0;j<6;j++)
			flagFound[i][j] = 0;

	pageFilled = malloc(page->size + N_BYTES_PARAMS);
	//printf("Page size:%d\n",page->size);

	if(strncmp(pageName,"/parametri_di_centrale.html",strlen("parametri_di_centrale"))==0)
	{
		fd = fopen("webserver.sav","r");		
		while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
		{
			if(strstr(tmpString,"\"central\":{")!=NULL)
			{
				extractValFromJson(tmpString, "type", central.centralType, STRING_TYPE);				
				extractValFromJson(tmpString, "model", central.centralModel, STRING_TYPE);
				extractValFromJson(tmpString, "connection", central.centralParam.connection, STRING_TYPE);
				central.centralParam.serialPort = extractValFromJson(tmpString, "serialPort", NULL, INT_TYPE);				 
				central.centralParam.plant = extractValFromJson(tmpString, "plant", NULL, INT_TYPE);				 
				central.centralParam.address = extractValFromJson(tmpString, "address", NULL, INT_TYPE);				 
				central.centralParam.baudrate = extractValFromJson(tmpString, "baudrate", NULL, INT_TYPE);				 
				extractValFromJson(tmpString, "ip", valStr, STRING_TYPE);
				central.centralParam.ip.addr1 = atoi(strtok(valStr,"."));
				central.centralParam.ip.addr2 = atoi(strtok(NULL,"."));
				central.centralParam.ip.addr3 = atoi(strtok(NULL,"."));
				central.centralParam.ip.addr4 = atoi(strtok(NULL,"."));
				central.centralParam.networkPort = extractValFromJson(tmpString, "networkPort", NULL, INT_TYPE);				 
				central.centralParam.numeration = extractValFromJson(tmpString, "numeration", NULL, INT_TYPE);				 
				extractValFromJson(tmpString, "code", central.centralParam.code, STRING_TYPE);				 
				extractValFromJson(tmpString, "passphrase", central.centralParam.passphrase, STRING_TYPE);				 
				extractValFromJson(tmpString, "id", central.centralParam.id, STRING_TYPE);				 
				central.centralParam.registerDimension = extractValFromJson(tmpString, "registerDimension", NULL, INT_TYPE);				 
				central.centralParam.polling = extractValFromJson(tmpString, "polling", NULL, INT_TYPE);				 
				central.centralParam.inputBalance = extractValFromJson(tmpString, "inputBalance", NULL, INT_TYPE);				 
				for(i=0;i<8;i++)
				{
					tmpPointer = strstr(tmpString,"\"in\":[");
					if(tmpPointer != NULL)							// search input field
					{
						sprintf(valStr,"\"idx\":%d",i);
						tmpPointer = strstr(tmpPointer,valStr);
						if(tmpPointer!=NULL)
						{
							central.inputs[i].function = extractValFromJson(tmpPointer, "tipo", NULL, INT_TYPE);
							extractValFromJson(tmpPointer, "descr", central.inputs[i].description, STRING_TYPE);
							central.inputs[i].allDayActive = extractValFromJson(tmpPointer, "h24", NULL, INT_TYPE);
							central.inputs[i].delay = extractValFromJson(tmpPointer, "ritardo", NULL, INT_TYPE);
							central.inputs[i].delayType = extractValFromJson(tmpPointer, "tipo_rit", NULL, INT_TYPE);
							central.inputs[i].restore = extractValFromJson(tmpPointer, "ripristino", NULL, INT_TYPE);
							central.inputs[i].restoreCondition = extractValFromJson(tmpPointer, "cond", NULL, INT_TYPE);		
						}						
					}
				}						
			}						
		}
		fclose(fd);		
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
				
				changeRes=0;
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,central.centralType,pageFilled,&newPageIndex,SELECT))&0x01;				
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,central.centralModel,pageFilled,&newPageIndex,SELECT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,central.centralParam.connection,pageFilled,&newPageIndex,SELECT))&0x01;
				switch(central.centralParam.serialPort)
				{
					case 0:
						sprintf(tmpString,"com1");
						break;
					case 1:
						sprintf(tmpString,"com2");
						break;
					case 2:
						sprintf(tmpString,"usb1");
						break;
					case 3:
						sprintf(tmpString,"usb2");
						break;
					case 4:
						sprintf(tmpString,"usb3");
						break;
				}				
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;				
				sprintf(tmpString,"%d",central.centralParam.plant);
				changeRes |= (~changeValInHtmlPage(pageRow,"defPlant",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.address);
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierId",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"defId",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.baudrate);
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.ip.addr1);				
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierIP1",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofireIP1",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.ip.addr2);								
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierIP2",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofireIP2",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.ip.addr3);								
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierIP3",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofireIP3",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				sprintf(tmpString,"%d",central.centralParam.ip.addr4);								
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierIP4",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;	
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofireIP4",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;	
				sprintf(tmpString,"%d",central.centralParam.networkPort);								
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierPort",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofirePort",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				if(central.centralParam.numeration == 0)
					changeRes |= (~changeValInHtmlPage(pageRow,NULL,"standard",pageFilled,&newPageIndex,SELECT))&0x01;
				else
					changeRes |= (~changeValInHtmlPage(pageRow,NULL,"stdRiass",pageFilled,&newPageIndex,SELECT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofireCode",central.centralParam.code,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"tecnofirePass",central.centralParam.passphrase,pageFilled,&newPageIndex,INPUT))&0x01;				
				changeRes |= (~changeValInHtmlPage(pageRow,"detfireAdd",central.centralParam.id,pageFilled,&newPageIndex,INPUT))&0x01;	
				sprintf(tmpString,"%d",central.centralParam.registerDimension);								
				changeRes |= (~changeValInHtmlPage(pageRow,"defMaxReg",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;		
				sprintf(tmpString,"%d",central.centralParam.polling);								
				changeRes |= (~changeValInHtmlPage(pageRow,"notifierPolling",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;			
				changeRes |= (~changeValInHtmlPage(pageRow,"defPolling",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				switch(central.centralParam.inputBalance)
				{
					case 1:
						sprintf(tmpString,"triple");
						break;
					case 2:
						sprintf(tmpString,"onOffNA");
						break;
					case 3:
						sprintf(tmpString,"onOffNC");
						break;					
				}				
				changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;
				if(strcmp(central.centralType,"local")==0)
				{
					for(i=0;i<8;i++)
					{
						sprintf(tmpString,"in%dFunction",i+1);
						if(strstr(pageRow,tmpString) != NULL)
							flagFound[i][0] = 1;
						else if(flagFound[i][0])
						{			
							switch(central.inputs[i].function)
							{
								case COND_ALARM:
									sprintf(tmpString,"alarm");
									break;
								case COND_FAIL:
									sprintf(tmpString,"broken");
									break;
								case COND_EXCL:
									sprintf(tmpString,"exclusion");
									break;
								case COND_BYPASS:
									sprintf(tmpString,"bypass");
									break;								
							}			
							if(strstr(pageRow,tmpString) != NULL){
								flagFound[i][0] = 0;
								changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;
							}									
						}
						sprintf(tmpString,"in%dDesc",i+1);
						changeRes |= (~changeValInHtmlPage(pageRow,tmpString,central.inputs[i].description,pageFilled,&newPageIndex,INPUT))&0x01;													
						sprintf(tmpString,"in%denable24h",i+1);
						if(strstr(pageRow,tmpString) != NULL)
							flagFound[i][1] = 1;
						else if(flagFound[i][1])
						{							
							if(central.inputs[i].allDayActive == ON){
								if(strstr(pageRow,"\"on\"") != NULL){
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"on",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][1] = 0;
								}
							}
							else{
								if(strstr(pageRow,"off") != NULL){
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"off",pageFilled,&newPageIndex,SELECT))&0x01;							
									flagFound[i][1] = 0;
								}
							}
						}
						sprintf(tmpString,"in%dDelay",i+1);
						sprintf(tmpPointer,"%d",central.inputs[i].delay);
						changeRes |= (~changeValInHtmlPage(pageRow,tmpString,tmpPointer,pageFilled,&newPageIndex,INPUT))&0x01;
						sprintf(tmpString,"in%dDelayType",i+1);
						if(strstr(pageRow,tmpString) != NULL)
							flagFound[i][2] = 1;
						else if(flagFound[i][2])
						{							
							if(central.inputs[i].delayType == PULSE){
								if(strstr(pageRow,"pulse") != NULL){
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"pulse",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][2] = 0;
								}
							}
							else{
								if(strstr(pageRow,"continuous") != NULL){
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"continuous",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][2] = 0;
								}
							}
						}
						sprintf(tmpString,"in%dRestore",i+1);
						if(strstr(pageRow,tmpString) != NULL)
							flagFound[i][3] = 1;
						else if(flagFound[i][3])
						{
							if(central.inputs[i].restore == ON){
								if(strstr(pageRow,"\"on\"") != NULL){
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"on",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][3] = 0;
								}
							}
							else{
								if(strstr(pageRow,"off") != NULL){								
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"off",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][3] = 0;
								}
							}
						}
						sprintf(tmpString,"in%dRestoreCondition",i+1);
						if(strstr(pageRow,tmpString) != NULL)
							flagFound[i][4] = 1;
						else if(flagFound[i][4])
						{
							if(central.inputs[i].restoreCondition == BYPASS){
								if(strstr(pageRow,"bypass") != NULL){								
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"bypass",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][4] = 0;
								}
							}
							else{
								if(strstr(pageRow,"input") != NULL){								
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,"input",pageFilled,&newPageIndex,SELECT))&0x01;
									flagFound[i][4] = 0;
								}
							}
						}
					}

				}	
				if(changeRes == 0)															// no value found
					newPageIndex += pageRowIdx - old_pageRowIdx + 1;									
				
				if(pageRow != NULL)	
					free(pageRow);

				old_pageRowIdx = ++pageRowIdx;
			}
		}
		printf("Ho finito di fare il fillpage\n");
		*(pageFilled+newPageIndex) = '\0';		
		page->data = malloc(strlen(pageFilled));
		memcpy((char *)(page->data),pageFilled,strlen(pageFilled));
		page->size = strlen(pageFilled);
	}
	else if(strncmp(pageName,"/parametri_di_sistema.html",strlen("parametri_di_sistema"))==0)
	{
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

		fd = fopen("webserver.sav","r");		
		while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
		{
			if(strstr(tmpString,"\"central\":{")!=NULL)
			{
				for(i=0;i<5;i++)
				{
					tmpPointer = strstr(tmpString,"\"out\":[");
					if(tmpPointer != NULL)							// search output field
					{						
						sprintf(valStr,"\"idx\":%d",i);
						tmpPointer = strstr(tmpPointer,valStr);
						if(tmpPointer!=NULL)
						{				
							extractValFromJson(tmpPointer, "descr", output[i].description, STRING_TYPE);
							output[i].condition = extractValFromJson(tmpPointer, "cond", NULL, INT_TYPE);
							output[i].normalState = extractValFromJson(tmpPointer, "na_nc", NULL, INT_TYPE);
							output[i].duration = extractValFromJson(tmpPointer, "durata", NULL, INT_TYPE);
							output[i].type = extractValFromJson(tmpPointer, "tipo", NULL, INT_TYPE);
						}						
					}
				}
			}
		}
		fclose(fd);

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
						changeRes=0;
						for(i=0;i<5;i++)
						{
							sprintf(tmpString,"descOut%d",i+1);
							changeRes |= (~changeValInHtmlPage(pageRow,tmpString,output[i].description,pageFilled,&newPageIndex,INPUT))&0x01;														
							sprintf(tmpString,"conditionOut%d",i+1);
							if(strstr(pageRow,tmpString) != NULL)
								flagFound[i][0] = 1;
							else if(flagFound[i][0])
							{			
								switch(output[i].condition)
								{
									case COND_ALARM:
										sprintf(tmpString,"alarm");
										break;
									case COND_FAIL:
										sprintf(tmpString,"broken");
										break;
									case COND_EXCL:
										sprintf(tmpString,"exclusion");
										break;
									case COND_BYPASS:
										sprintf(tmpString,"bypass");
										break;		
									case COND_REMOTE:
										sprintf(tmpString,"diagnostic");
										break;									
								}			
								if(strstr(pageRow,tmpString) != NULL){
									flagFound[i][0] = 0;
									changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;
								}									
							}
							sprintf(tmpString,"normalStateOut%d",i+1);
							if(strstr(pageRow,tmpString) != NULL)
								flagFound[i][1] = 1;
							else if(flagFound[i][1])
							{							
								if(output[i].normalState == ON){
									if(strstr(pageRow,"\"on\"") != NULL){
										changeRes |= (~changeValInHtmlPage(pageRow,NULL,"on",pageFilled,&newPageIndex,SELECT))&0x01;
										flagFound[i][1] = 0;
									}
								}
								else{
									if(strstr(pageRow,"off") != NULL){
										changeRes |= (~changeValInHtmlPage(pageRow,NULL,"off",pageFilled,&newPageIndex,SELECT))&0x01;							
										flagFound[i][1] = 0;
									}
								}
							}
							sprintf(tmpPointer,"%d",output[i].duration);
							sprintf(tmpString,"durationOut%d",i+1);
							changeRes |= (~changeValInHtmlPage(pageRow,tmpString,tmpPointer,pageFilled,&newPageIndex,INPUT))&0x01;
							sprintf(tmpString,"typeOut%d",i+1);
							if(strstr(pageRow,tmpString) != NULL)
								flagFound[i][2] = 1;
							else if(flagFound[i][2])
							{							
								if(output[i].type == TYPE_CONTINUOUS){
									if(strstr(pageRow,"continuous") != NULL){
										changeRes |= (~changeValInHtmlPage(pageRow,NULL,"continuous",pageFilled,&newPageIndex,SELECT))&0x01;
										flagFound[i][2] = 0;
									}
								}
								else{
									if(strstr(pageRow,"followState") != NULL){
										changeRes |= (~changeValInHtmlPage(pageRow,NULL,"followState",pageFilled,&newPageIndex,SELECT))&0x01;							
										flagFound[i][2] = 0;
									}
								}
							}
						}
						if(changeRes==0)	
							newPageIndex += pageRowIdx - old_pageRowIdx + 1;											
				}
				if(pageRow != NULL)	
					free(pageRow);

				old_pageRowIdx = ++pageRowIdx;
			}
		}
		*(pageFilled+newPageIndex) = '\0';
		/*if(page->data != NULL)
			free(page->data);*/
		page->data = malloc(strlen(pageFilled));
		memcpy((char *)(page->data),pageFilled,strlen(pageFilled));
		page->size = strlen(pageFilled);	
	}
	else if(strncmp(pageName,"/parametri_di_supervisione.html",strlen("parametri_di_supervisione"))==0)
	{
		fd = fopen("webserver.sav","r");		
		while(fgets(tmpString,sizeof(tmpString),fd) != NULL)
		{
			tmpPointer = strstr(tmpString,"\"sv\":{");
			if(tmpPointer!=NULL)
			{
				extractValFromJson(tmpPointer, "descr", sv.plantLabel, STRING_TYPE);				
				sv.hiCloudEn = extractValFromJson(tmpPointer, "hiCloud", NULL, INT_TYPE);
				sv.hiCloudPlantId = extractValFromJson(tmpPointer, "hiCloudId", NULL, INT_TYPE);
				extractValFromJson(tmpPointer, "url", sv.hiCloudRegister, STRING_TYPE);
				sv.cidEn = extractValFromJson(tmpPointer, "cid", NULL, INT_TYPE);
				extractValFromJson(tmpPointer, "cidReg1", sv.cidRegister1, STRING_TYPE);
				extractValFromJson(tmpPointer, "cidReg2", sv.cidRegister2, STRING_TYPE);
				extractValFromJson(tmpPointer, "pin", sv.pinSim, STRING_TYPE);
				extractValFromJson(tmpPointer, "apn", sv.apnSim, STRING_TYPE);
				extractValFromJson(tmpPointer, "user", sv.userSim, STRING_TYPE);
				extractValFromJson(tmpPointer, "pwd", sv.pwdSim, STRING_TYPE);				
				for(i=0;i<8;i++)
				{					
					tmpPointer = strstr(tmpString,"\"phone\":[");
					if(tmpPointer != NULL)							// search output field
					{						
						sprintf(valStr,"\"idx\":%d",i);
						tmpPointer = strstr(tmpPointer,valStr);
						if(tmpPointer!=NULL)
						{										
							extractValFromJson(tmpPointer, "descr", sv.phone[i].description, STRING_TYPE);
							extractValFromJson(tmpPointer, "num", sv.phone[i].number, STRING_TYPE);
							sv.phone[i].sms = extractValFromJson(tmpPointer, "sms", NULL, INT_TYPE);
							sv.phone[i].voice = extractValFromJson(tmpPointer, "voce", NULL, INT_TYPE);
							sv.phone[i].alertType = extractValFromJson(tmpPointer, "tipo", NULL, INT_TYPE);
							sv.phone[i].cmd = extractValFromJson(tmpPointer, "cmd", NULL, INT_TYPE);						
						}
					}
				}
			}
		}
		fclose(fd);

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

				changeRes=0;
				changeRes |= (~changeValInHtmlPage(pageRow,"plantLabel",sv.plantLabel,pageFilled,&newPageIndex,INPUT))&0x01;
				if(sv.hiCloudEn == 0)										// hiCloud disabled
					sprintf(tmpString,"off");
				else														// hiCloud enabled
					sprintf(tmpString,"on");				
				changeRes |= (~changeValInHtmlPage(pageRow,"enableHiCloud",tmpString,pageFilled,&newPageIndex,CHECKBOX))&0x01;							
				sprintf(tmpString,"%d",sv.hiCloudPlantId);
				changeRes |= (~changeValInHtmlPage(pageRow,"plantId",tmpString,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"urlRegister",sv.hiCloudRegister,pageFilled,&newPageIndex,INPUT))&0x01;
				if(sv.cidEn == 0)											// Contact id disabled
					sprintf(tmpString,"off");					
				else														// Contact id enabled
					sprintf(tmpString,"on");					
				changeRes |= (~changeValInHtmlPage(pageRow,"enableCid",tmpString,pageFilled,&newPageIndex,CHECKBOX))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"urlCid1",sv.cidRegister1,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"urlCid2",sv.cidRegister2,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"pin",sv.pinSim,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"apn",sv.apnSim,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"user",sv.userSim,pageFilled,&newPageIndex,INPUT))&0x01;
				changeRes |= (~changeValInHtmlPage(pageRow,"pwd",sv.pwdSim,pageFilled,&newPageIndex,INPUT))&0x01;

				for(i=0;i<8;i++)
				{
					sprintf(tmpPointer,"mexCell%d",i+1);
					if(sv.phone[i].sms == 0)									// SMS disabled
						sprintf(tmpString,"off");					
					else														// SMS enabled
						sprintf(tmpString,"on");					
					changeRes |= (~changeValInHtmlPage(pageRow,tmpPointer,tmpString,pageFilled,&newPageIndex,CHECKBOX))&0x01;
					sprintf(tmpPointer,"voiceCell%d",i+1);
					if(sv.phone[i].voice == 0)									// call disabled
						sprintf(tmpString,"off");					
					else														// call enabled
						sprintf(tmpString,"on");					
					changeRes |= (~changeValInHtmlPage(pageRow,tmpPointer,tmpString,pageFilled,&newPageIndex,CHECKBOX))&0x01;
					sprintf(tmpPointer,"cmdCell%d",i+1);
					if(sv.phone[i].cmd == 0)									// Command disabled
						sprintf(tmpString,"off");					
					else														// Command enabled
						sprintf(tmpString,"on");					
					changeRes |= (~changeValInHtmlPage(pageRow,tmpPointer,tmpString,pageFilled,&newPageIndex,CHECKBOX))&0x01;
					sprintf(tmpString,"descCell%d",i+1);
					changeRes |= (~changeValInHtmlPage(pageRow,tmpString,sv.phone[i].description,pageFilled,&newPageIndex,INPUT))&0x01;
					sprintf(tmpString,"cell%d",i+1);
					changeRes |= (~changeValInHtmlPage(pageRow,tmpString,sv.phone[i].number,pageFilled,&newPageIndex,INPUT))&0x01;
					sprintf(tmpString,"alarmCell%d",i+1);
					if(strstr(pageRow,tmpString) != NULL)
						flagFound[i][0] = 1;
					else if(flagFound[i][0])
					{			
						switch(sv.phone[i].alertType)
						{
							case ALARM:
								sprintf(tmpString,"alarm");
								break;
							case DIAGNOSTIC:
								sprintf(tmpString,"diagnostic");
								break;
							case ALARM_DIAGNOSTIC:
								sprintf(tmpString,"alarm_diagnostic");
								break;
						}			
						if(strstr(pageRow,tmpString) != NULL){
							flagFound[i][0] = 0;
							changeRes |= (~changeValInHtmlPage(pageRow,NULL,tmpString,pageFilled,&newPageIndex,SELECT))&0x01;
						}									
					}
				}
				if(changeRes==0)	
					newPageIndex += pageRowIdx - old_pageRowIdx + 1;											

				if(pageRow != NULL)	
					free(pageRow);

				old_pageRowIdx = ++pageRowIdx;
			}
		}
		*(pageFilled+newPageIndex) = '\0';
		/*if(page->data != NULL)
			free(page->data);*/
		page->data = malloc(strlen(pageFilled));
		memcpy((char *)(page->data),pageFilled,strlen(pageFilled));
		page->size = strlen(pageFilled);
	}

	if(pageFilled != NULL)
		free(pageFilled);
}
/* */
