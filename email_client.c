#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// email inbox size
#define Inbox_Size 20

// attributes of an email message 
struct email{
	char subj[100], msg[1000], from[40], time[40];
};
typedef struct email email;

// function used to find a specific word (delimiter) in a text (input) and split it for string manipulation
char *multi_tok(char *input, char *delimiter) {
    static char *string;
    if (input != NULL)
        string = input;

    if (string == NULL)
        return string;

    char *end = strstr(string, delimiter);
    if (end == NULL) {
        char *temp = string;
        string = NULL;
        return temp;
    }

    char *temp = string;

    *end = '\0';
    string = end + strlen(delimiter);
    return temp;
}

// function that 'builds' the SMTP header of an email message
char* MailHeader(const char *from, const char *to,const char *subject, const char *mime_type, const char* charset) {
	
	time_t now;
	time(&now);
	char *app_brand = "Network Programming Lab";
	char *mail_header = NULL;
	char date_buff[26];
	char Branding[6 + strlen(date_buff) + 2 + 10 + strlen(app_brand) + 1 + 1];
	char Sender[6 + strlen(from) + 1 + 1];
	char Recip[4 + strlen(to) + 1 + 1];
	char Subject[8 + 1 + strlen(subject) + 1 + 1];
	char mime_data[13 + 1 + 3 + 1 + 1 + 13 + 1 + strlen(mime_type) + 1 + 1 + 8 + strlen(charset) + 1 + 1 + 2];
	
	strftime(date_buff, (33), "%a , %d %b %Y %H:%M:%S", localtime(&now));
	
	sprintf(Branding, "Date: %s\r\nX-Mailer: %s\r\n", date_buff, app_brand);
	sprintf(Sender, "From: %s\r\n", from);
	sprintf(Recip, "To: %s\r\n", to);
	sprintf(Subject, "Subject: %s\r\n", subject);
	sprintf(mime_data, "MIME-Version: 1.0\r\nContent-type: %s; charset = %s\r\n\r\n", mime_type,charset);

	int mail_header_length = strlen(Branding) + strlen(Sender) + strlen(Recip) + strlen(Subject) + strlen(mime_data) + 10;

	mail_header = (char*) malloc(mail_header_length*sizeof(char));

	memcpy(&mail_header[0], &Branding, strlen(Branding));
	memcpy(&mail_header[0 + strlen(Branding)], &Sender, strlen(Sender));
	memcpy(&mail_header[0 + strlen(Branding) + strlen(Sender)], &Recip, strlen(Recip));
	memcpy(&mail_header[0 + strlen(Branding) + strlen(Sender) + strlen(Recip)], &Subject, strlen(Subject));
	memcpy(&mail_header[0 + strlen(Branding) + strlen(Sender) + strlen(Recip) + strlen(Subject)], &mime_data,strlen(mime_data));
	return mail_header;
}

// converts server name into IP address
const char* GetIPAddress(const char* target_domain){
	const char* target_ip;
	struct in_addr *host_address;
	struct hostent *raw_list = gethostbyname(target_domain);
	int i = 0;
	for (i; raw_list->h_addr_list[i] != 0; i++){
		host_address = raw_list->h_addr_list[i];
		target_ip = inet_ntoa(*host_address);	
	}

	return target_ip;
}	 

// creates a socket and initiates a connection between client and a target host
int connectToServer(const char* server_address,int port_num){

	int socket_fd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port_num);
	if(inet_pton(AF_INET, GetIPAddress(server_address), &addr.sin_addr) == 1) {
		connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr));
	}

	return socket_fd;
}

// alphabet available for encoding of text message
static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// text encoding 
int Base64encode(char *encoded, const char *string, int len) {
	    int i;
	    char *p;

	    p = encoded;
	    for (i = 0; i < len - 2; i += 3) {
		    *p++ = basis_64[(string[i] >> 2) & 0x3F];
		    *p++ = basis_64[((string[i] & 0x3) << 4) |
				    ((int) (string[i + 1] & 0xF0) >> 4)];
		    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
				    ((int) (string[i + 2] & 0xC0) >> 6)];
		    *p++ = basis_64[string[i + 2] & 0x3F];
	    }

	    if (i < len) {
		    *p++ = basis_64[(string[i] >> 2) & 0x3F];

		    if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		    } else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				 ((int) (string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		    }

		    *p++ = '=';
	    }

	    *p++ = '\0';
	    return p - encoded;
}


// first page of the application. Options are starting login process or quitting
void *main_page(char *ch){
	printf("\n================ MAIN PAGE ================\n");
	printf("\n1. Login\n");
	printf("\n2. Quit\n");
	printf("\n===========================================\n");

	printf("Make your selection: ");
	scanf("%s", ch);
	
	// in case of invalid entry
	while(atoi(ch) != 1 && atoi(ch) != 2){
		printf("The selection isn't valid. Please try again.\n\n");
		printf("Make your selection: ");
		scanf("%s",ch);
	}
}

// clears strings for reuse
void clear_strings(char *UID, char *UPD, char *FROM, char *SUBJ, char *MSG){
	memset(UID,0,sizeof(UID));
	memset(UPD,0,sizeof(UPD));
	memset(FROM,0,sizeof(FROM));
	memset(SUBJ,0,sizeof(SUBJ));
	memset(MSG,0,sizeof(MSG));
}

// page where user enters credentials
// UID - username with @, UPD - password, FROM - username in brackets ('< >') for further protocol purposes
// and domain - server domain ('gmail.com' for example)
void login_process(char *UID, char *UPD, char *FROM, char *domain) {
	
	int login_success = 0;	
	char *remain = (char *) malloc(sizeof(char *));
		
	printf("\n================ LOGIN PAGE ================\n");

	printf("\nEnter email ID: ");	
	scanf("%s", UID);
	strtok(UID, "\n");
	strcat(FROM, "<");
	strcat(FROM, UID);
	strcat(FROM, ">");
	getchar();

	printf("\nEnter email password: ");
	scanf("%s", UPD);
}

// main page after successful login. User is immediately able to send email, check mailbox or quit
void login_page(char *UID, char *ch) {
	
	// filters username out of entire email username for greeting purpose (e.g. 'gabriel' from 'gabriel@gmail.com')	
	strtok(UID, "@");	
	printf("\n============= Welcome '%s' =============\n", UID);
	

	printf("\n1. Send Email\n");
	printf("\n2. Check Mailbox\n");
	printf("\n3. Sign out\n");
	printf("\n===========================================\n");
	
	printf("Make your selection: ");
	scanf("%s", ch);

	// in case of invalid entry	
	while(atoi(ch) != 1 && atoi(ch) != 2 && atoi(ch) != 3){
		printf("The selection isn't valid. Please try again.\n\n");
		printf("Make your selection: ");
		scanf("%s", ch);
	}
}


// process of greeting SMTP server, authenticating, sending header and following email parameters according to protocol
// in order to send an email to destination

// for header: FROM - sender, SUBJ - subject, MSG - message text, ssl - security layer process, RID_rep - reply recipient
// opt - indicates whether it is a new message, reply or forward of an old message.  
void send_email(char *UID, char *UPD, char *FROM, char *SUBJ, char *MSG, char *domain, SSL *ssl, char *RID_rep, char *opt){
			
	// printf("\nSUBJ: %s\n", SUBJ);	
	// printf("\nMSG: %s\n", MSG);
	
	// TO is message recipient, TO_header is recipient between brackets and RID auxiliary variable
	char TO[30] = "";
	char TO_header[30] = "";
	char bin;
	int i = 0;
	char RID[30] = "";
	
	// recv_buff - buffer for messages from SMTP server, recvd - length of messages in total
	// sdsd - length of received message at each time
	int recvd = 0;
	char recv_buff[4768];
	int sdsd;
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
	
	// buff - buffer for messages to be sent to SMTP server
	// greeting process	
	char buff[1000];
	strcpy(buff, "EHLO smtp.gmail.com");
	strcat(buff, domain); // HEEEEEEEEEEEY is it necessary?
	strcat(buff, "\r\n");
	SSL_write(ssl, buff,strlen(buff));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	// security layer protocol process
	char buff3[1000];
	strcpy(buff3, "STARTTLS");
	strcat(buff3, "\r\n");
	SSL_write(ssl, buff3, strlen(buff3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	// authentication start process
	char _cmd2[1000];
	strcpy(_cmd2, "AUTH LOGIN\r\n");
	int dfdf = SSL_write(ssl, _cmd2, strlen(_cmd2));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	// 'encoded' username is sent here
	char _cmd3[1000];
	Base64encode(_cmd3, UID, strlen(UID));
	strcat(_cmd3, "\r\n");
	SSL_write(ssl, _cmd3,strlen(_cmd3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	// 'encoded' password is sent here
	char _cmd4[1000];
	Base64encode(_cmd4, UPD, strlen(UPD));
	strcat(_cmd4, "\r\n");
	SSL_write(ssl,_cmd4,strlen(_cmd4));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
				
	// request to send a message
	char _cmd5[1000];
	strcpy(_cmd5,"MAIL FROM:");
	strcat(_cmd5, FROM);
	strcat(_cmd5, "\r\n");
	SSL_write(ssl, _cmd5, strlen(_cmd5));
	char skip[1000]; // WHY SKIPPPP?
	sdsd = SSL_read(ssl, skip, sizeof(skip));

	// recipients are informed here
	// this case for new subject message
	if (opt[0]!='r' && opt[0]!='f'){
		int TO_num = 0;

		printf("\nEnter the number of recipients:");
		scanf("%d",&TO_num);
		scanf("%c",&bin);

		// considers the case of multiple recipients
		for(i = 0; i < TO_num; i++) {
							
			printf("Recipient email %d:", (i+1));
			
			fgets(RID, sizeof(RID), stdin);
			strtok(RID, "\n");
			strcat(TO, "<");
			strcat(TO, RID);
			strcat(TO, ">");
			strcat(TO_header, RID);
			strcat(TO_header, "; ");						
			
			char _cmd6[1000];
			strcpy(_cmd6, "RCPT TO: ");
			strcat(_cmd6, TO); 
			printf("\nTO: %s\n",TO);
			strcat(_cmd6, "\r\n");
			
			SSL_write(ssl, _cmd6, strlen(_cmd6));
			
			sdsd = SSL_read(ssl, recv_buff + recvd, sizeof (recv_buff) - recvd);
		      	recvd += sdsd;	
			strcpy(RID, "");
			strcpy(TO, "");	
		}

	}
	// case of a forward or reply message
	else {
		printf("\nReply / Forward Message here!\n");
		//strtok(RID_rep, "\n");
		//strcat(TO, "<");
		strcat(TO, RID_rep);
		//strcat(TO, ">");
		strcat(TO_header, RID_rep);
		//strcat(TO_header, "; ");						
					
		char _cmd6[1000];
		strcpy(_cmd6, "RCPT TO: ");
		strcat(_cmd6, TO); 
		printf("\nTO: %s\n",TO);
		strcat(_cmd6, "\r\n");
			
		SSL_write(ssl, _cmd6, strlen(_cmd6));
		
		sdsd = SSL_read(ssl, recv_buff + recvd, sizeof (recv_buff) - recvd);
		recvd += sdsd;	
		strcpy(RID_rep, "");
		strcpy(TO, "");	
	}
	
	// starts to send the header and message
	char _cmd7[1000];
	strcpy(_cmd7,"DATA\r\n");
	SSL_write(ssl, _cmd7,strlen(_cmd7));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	char *header = MailHeader(FROM, TO_header, SUBJ, "text/plain", "US-ASCII");
	printf("\nHEADER:\n%s \n", header);

	SSL_write(ssl, header, strlen(header));
					
	char _cmd8[1000];
	strcpy(_cmd8,MSG);
	SSL_write(ssl,_cmd8,strlen(_cmd8));
	
	// end of SMTP commands
	char _cmd9[1000];
	strcpy(_cmd9,"\r\n.\r\n.");
	SSL_write(ssl,_cmd9,strlen(_cmd9));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;		

	char _cmd10[1000];
	strcpy(_cmd10,"QUIT\r\n");
	SSL_write(ssl, _cmd10,strlen(_cmd10));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;
	// printf("(0)%s\r\n", recv_buff);
	free(header);	
	
}

// here the SMTP server checks if credentials are correct for login
// process is equal to beginning of sending email
void login_comands(char *UID, char * UPD, SSL *ssl, char *domain, int *in) {
	
	int recvd = 0;
	char recv_buff[4768], copy[4768];
	
	int sdsd;
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
	
		
	char buff[1000];
	strcpy(buff, "EHLO smtp.gmail.com");
	strcat(buff, domain);
	strcat(buff, "\r\n");
	SSL_write(ssl, buff,strlen(buff));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	char buff3[1000];
	strcpy(buff3, "STARTTLS");
	strcat(buff3, "\r\n");
	SSL_write(ssl, buff3, strlen(buff3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	char _cmd2[1000];
	strcpy(_cmd2, "AUTH LOGIN\r\n");
	int dfdf = SSL_write(ssl, _cmd2, strlen(_cmd2));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	char _cmd3[1000];
	Base64encode(_cmd3, UID, strlen(UID));
	strcat(_cmd3, "\r\n");
	SSL_write(ssl, _cmd3,strlen(_cmd3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

	char _cmd4[1000];
	Base64encode(_cmd4, UPD, strlen(UPD));
	strcat(_cmd4, "\r\n");
	SSL_write(ssl,_cmd4,strlen(_cmd4));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
	
	char _cmd10[1000];
	strcpy(_cmd10,"QUIT\r\n");
	SSL_write(ssl, _cmd10, strlen(_cmd10));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
	//printf("(0)%s\r\n", recv_buff);	
	
	// here the SMTP reply to authentication try is checked
	// variable 'in' is used through the main to indicate user logged 
	if(strstr(recv_buff, "2.7.0 Accepted") != NULL)
		*in = 1;
	else{
		*in = 0;
		printf("\n>> Login Unsuccessful! Please try again! <<\n");
	}
}
 
// process of deleting message (via POP3 server)
// variable 'emails' is array of email in the mailbox, and 'del' the number of the message to be deleted
void email_delete(char *UID, char *UPD, SSL *ssl, email *emails, int del) {
					
	int recvd = 0, i = 0;
	char recv_buff[4768];
	int sdsd;
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
	
	// authentication with POP3 server
	char buff[1000];
	strcpy(buff, "USER ");
	strcat(buff, UID);
	strcat(buff, "\r\n");
	SSL_write(ssl, buff,strlen(buff));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;
	char buff3[1000];
	strcpy(buff3, "PASS ");
	strcat(buff3, UPD);					
	strcat(buff3, "\r\n");
	SSL_write(ssl, buff3, strlen(buff3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;
				
										
	// command DELE + number of the email to POP3				
	char *token;
	char *trash;
	char _cmd2[1000];
	char email_list[20000];
	strcpy(_cmd2, "LIST\r\n"); // NECESSARY?
	SSL_write(ssl, _cmd2, strlen(_cmd2)); // NECESSARY?
	sdsd = SSL_read(ssl, email_list, sizeof(email_list));
	char buff4[1000];
	char sdel[10];
	strcpy(buff4, "DELE ");
	sprintf(sdel, "%d", del);
	strcat(buff4,sdel);						
	strcat(buff4, "\r\n");
	SSL_write(ssl, buff4, strlen(buff4));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;			
		
	char _cmd10[1000];
	strcpy(_cmd10,"QUIT\r\n");
	SSL_write(ssl, _cmd10,strlen(_cmd10));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;

}

// this process access the mailbox in POP3 server and updates the array of emails, filtering information
// such as sender, time, subject and message text for each attribute of email struct
void check_mailbox(char *UID, char *UPD, SSL *ssl, email *emails, int *n_mes) {

	int recvd = 0, i=0;
	char recv_buff[4768];
	int sdsd;
				
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;
						
	char buff[1000];
	strcpy(buff, "USER ");
	strcat(buff, UID);
	strcat(buff, "\r\n");
	SSL_write(ssl, buff,strlen(buff));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd += sdsd;

	char buff3[1000];
	strcpy(buff3, "PASS ");
	strcat(buff3, UPD);					
	strcat(buff3, "\r\n");
	SSL_write(ssl, buff3, strlen(buff3));
	sdsd = SSL_read(ssl, recv_buff + recvd, sizeof(recv_buff) - recvd);
	recvd +=sdsd;
							
	char *token;
	char *trash;
	char _cmd2[1000];
	char email_list[20000];
	strcpy(_cmd2, "LIST\r\n");
	SSL_write(ssl, _cmd2, strlen(_cmd2));
	sdsd = SSL_read(ssl, email_list, sizeof(email_list));

	// filters the number of messages since " " is the specific delimiter			
	token = strtok(email_list, " ");
	token = strtok(NULL, " ");
	*n_mes = strtol(token, &trash, 10);
					
	printf("\nYou have in total ' %d ' messages in your inbox\n",*n_mes);
						
	if (*n_mes>=Inbox_Size)
		*n_mes=Inbox_Size;

	char _cmdmb[1000];
	char buffermb[10];

	// process to get sender, time, subject and text					
	for(i = 0; i < *n_mes; i++) {
		
		// RETR command retrieves all the data contained in an email				
		strcpy(_cmdmb,"RETR ");
		sprintf(buffermb, "%d", i + 1);
				
		strcat(_cmdmb, buffermb);
		strcat(_cmdmb, "\r\n");		
						
		SSL_write(ssl, _cmdmb, strlen(_cmdmb));

		//read message						
		char message[3000];
		char copy[3000];
		char *token_1; 
		
		//printf("\nFind info of %d\n",i+1);

		// requests the data coming until the end of the data of the email		
		while(SSL_read(ssl, message, sizeof(message)) != 0) {
						
			strcpy(copy, message);
			// locates substring indicating sender
			if(strstr(copy, "\nFrom: ") != NULL) {
				token_1 = multi_tok(copy, "\nFrom: ");
				token_1 = multi_tok(NULL, "\n");
				
				// update of info in array
				strcpy(emails[i].from, token_1);
			}
			
			// locates substring indicating time					
			strcpy(copy, message);
			if(strstr(message, "\nDate: ") != NULL) {
				token_1 = multi_tok(copy, "\nDate: ");
				token_1 = multi_tok(NULL, "\n");
				
				// update of info in array				
				strcpy(emails[i].time, token_1);
			}
			
			// locates substring indicating subject
			strcpy(copy, message);
			if(strstr(message, "\nSubject: ") != NULL) {
			
				token_1 = multi_tok(copy, "\nSubject: ");
				token_1 = multi_tok(NULL, "\n");
				
				// update of info in array
				strcpy(emails[i].subj, token_1);
			}				
			

			// locates substring indicating text and finally character encoding, which is in the
			// end of useful  information for general user
			// the program deals only with 'UTF-8', the most used in internet					
			strcpy(copy, message);
			if(strstr(message, "charset=\"UTF-8\"") != NULL) {
														
				token_1 = multi_tok(copy, "charset=\"UTF-8\"");	
				token_1 = multi_tok(NULL, "--");
				strcpy(emails[i].msg, token_1);
			}			
			
			// when email received was from sent from email client	
			else if (strstr(message, "charset = US-ASCII") != NULL) {
				token_1 = multi_tok(copy, "charset = US-ASCII");	
				token_1 = multi_tok(NULL, ".");
				strcpy(emails[i].msg, token_1);
			}	
			
			// end of message
			if(strstr(message, "\n.") != NULL) {
				break;
			}
		} 
		
		// clear the strings for next messages in the list
		memset(message, 0, sizeof(message));
		memset(copy, 0, sizeof(copy));
		memset(token_1, 0, sizeof(token_1));
	}	
}

// here the user visualizes the mailbox and can interact with messages, i.e. with this funtion user can reply, forward and delete messages
// which are processes redirected to other functions
void inbox_menu(int *n_mes, email *emails, SSL *ssl, char *SUBJ, char *FROM, char *RID_rep, char *opt, char *MSG, char *UID, char *UPD) {
	
	int n_del = 0;
	int i = 0;
	char option[10];	
	char ch[10], ch2[10], temp[10];	
	char *f_from=(char *) malloc(30);	
	char *bin=(char *) malloc(30);				
		
	// shows mailbox with sender, subject and time below each email
	printf("\n ================= EMAIL INBOX ================= \n");
	
	for(i=*n_mes-1;i>=0;i--){
		if(strcmp(emails[i].from,"")!=0)
			printf("\n%d: From: %s\n Subject: %s\n Time: %s\n\n",i+1,emails[i].from,emails[i].subj,emails[i].time);
	}

	printf("\n =============================================== \n");			
	
	// here options to read the text or delete an email or go back
	// variable 'option' indicates the option chosen
	printf(">> Options\n\t1.Read an Emaill\n\t2.Delete an Email\n\t3.Go back\n");					
	printf("\nChoose: ");
	scanf("%s", option);
	
	// while not selected 'go back' user stays in this inbox menu, i.e. the list of messages is shown after each complete interaction 
	while(atoi(option) != 3){
		printf("\nOption is %s\n", option);
		
		switch(atoi(option))
		{
			// read email option
			// variable 'ch' indicates option chosen of email to be read and is used for further option o interaction
			case 1:	
				printf("\nType number of email to read [emails %d-%d] or \n\n>> Go back[b] <<\n", 1, *n_mes);
				printf("\nChoose: ");
				scanf("%s", ch);
								
				while(ch[0] != 'b') {						
				
					if(atoi(ch) > 0 && atoi(ch) <= *n_mes){				
						printf("\n ================= Email (No.%d) ================== \n", atoi(ch));
				        	printf("\nFrom %s", emails[atoi(ch) - 1].from);							
						printf("\nSubj: %s", emails[atoi(ch) - 1].subj);						
						printf("\nMessage: %s", emails[atoi(ch) - 1].msg);
						printf("\n ================================================== \n");						
					} 
					// case of invalid number of email					
					else if(atoi(ch) <= 0 || atoi(ch)>*n_mes) {			
						printf("\nEmail does not exist! or option was not valid!\n\nPlease try again!\n\n");
											
					}
					
					strcpy(temp, ch);					
					
					// after reading text, user can reply, forward 				
					printf("\nType number of email to read [Emails: %d-%d] or \n\n>> Reply[r] or Forward[f] or Go back[b] <<\n", 1, *n_mes);		
					printf("\nChoose: ");
					scanf("%s", ch);
					
					// reply option - subject and sender are exported to 'send_email' process
					if(ch[0] == 'r')
					{
						strcpy(opt, ch);
						printf("\n>> Reply email Operation! << \n");
						
						bin = multi_tok(emails[atoi(temp) - 1].from, "<");
						f_from = multi_tok(NULL, ">");
						
						strcpy(RID_rep, "<");
						strcat(RID_rep, f_from);
						strcat(RID_rep, ">");						
						printf("\nTO: %s\n", RID_rep);
						
						memset(SUBJ, 0, sizeof(SUBJ));
						strcat(SUBJ, "(RE) ");
						strcat(SUBJ, emails[atoi(temp) - 1].subj);	
						strcat(SUBJ, "\n");						
						printf("\nSUBJ: %s\n", SUBJ);
						return;			
					}
					
					// forward option - text and subject are exported to 'send_email' process	
					if(ch[0]=='f')
					{
						strcpy(opt, ch);
						printf("\n>> Forward email Operation! << \n");

						strcpy(f_from,emails[atoi(temp) - 1].from);
						bin = multi_tok(f_from, "<");
						f_from = multi_tok(NULL, ">");
										
						memset(SUBJ, 0, sizeof(SUBJ));
						strcat(SUBJ, "(FW) from ");
						strcat(SUBJ, f_from);
						strcat(SUBJ, " / SUBJ: ");						
						strcat(SUBJ, emails[atoi(temp) - 1].subj);	
						strcat(SUBJ, "\n");						
						printf("\nSUBJ: %s\n", SUBJ);
						
						memset(MSG, 0, sizeof(MSG));						
						strcpy(MSG, emails[atoi(temp) - 1].msg);	
						printf("\nMSG: %s\n", MSG);
						return;			
					}								
				}
				break;
			
			// delete email option
			case 2:
				printf("\nType number of email to delete [emails %d-%d] or \n\n>> Go Back[b] <<\n", 1, *n_mes);
				printf("\nChoose: ");
				scanf("%s", ch);				
				while(ch[0] != 'b'){	
					if(atoi(ch) > 0 && atoi(ch) <= *n_mes){				
						// delete process handled by ssl_commands	
						ssl_commands(UID, UPD, FROM, SUBJ, MSG, "pop.gmail.com", "gmail.com", 995, 3, emails, &n_mes, RID_rep, opt, 1, atoi(ch));	
						strcpy(opt,"d");				 						 	return;
					} 
					// case of invalid number of email
					else if(atoi(ch)<=0 || atoi(ch)>*n_mes){			
						printf("\nEmail does not exist! or option was not valid!\n\n Please try again!\n\n");
					}								
				
					// user is asked about a new message to delete or to go back
					printf("\nType number of email to delete [emails %d-%d] or \n\n>> Go back[b] <<\n",1,*n_mes);		
					printf("\nChoose: ");	
					scanf("%s",ch);		
				}
				
				printf("\nDelete Process over!\n");
				break;
			
			// in case user typed command other than read or delete			
			default:
				printf("\nAn invalid choice has slipped through.\nPlease try again\n\n");
				
		}
		
		// mailbox is shown again after all interaction
		printf("\n ================= EMAIL INBOX ================= \n");
		for(i=*n_mes-1;i>=0;i--){
			if(strcmp(emails[i].from,"")!=0)
				printf("\n%d: From: %s\n Subject: %s\n Time %s\n\n", i+1, emails[i].from, emails[i].subj, emails[i].time);				
		}		
		
		printf("\n =============================================== \n");			
		printf(">> Options\n\t1.Read an Emaill\n\t2.Delete an Email\n\t3.GO Back\n");				
		printf("\nChoose: ");
		scanf("%s",option);
	}
	
	// end of loop when user selects 'go back' 
	printf("\n\nBack to main page!\n");
	memset(opt, 0, sizeof(opt));

	for(i = 0; i < Inbox_Size; i++)
		memset(&emails[i],0,sizeof(emails[i]));	
	
}



void ssl_commands(char *UID,char *UPD,char *FROM,char *SUBJ,char *MSG,char *domain_name,char *domain,int port_num,int sel,email *emails,int *n_mes,char *RID_rep,char *opt,int *in,int del){

	BIO *obj_bio = NULL;
	BIO *obj_out = NULL;
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	int connected_fd = 0;
	int ret, i,acc=0;
	
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	obj_bio = BIO_new(BIO_s_file());
	obj_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if(SSL_library_init() < 0) {
		BIO_printf(obj_out, "Open_SSL not initialize");
	} else {
		method = SSLv23_client_method();
		if((ctx = SSL_CTX_new(method)) == NULL) {
			BIO_printf(obj_out, "OpenSSL context not initialize");
		} else {
			SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
			ssl = SSL_new(ctx);
			connected_fd = connectToServer(domain_name,port_num);
			
			if(connected_fd != 0) {
				BIO_printf(obj_out, "\nConnected successfully\n");
				SSL_set_fd(ssl, connected_fd);
				
				if(SSL_connect(ssl) != 1) {
					BIO_printf(obj_out, "SSL session not created");
				} else {
					if (sel==0){
						login_comands(UID,UPD,ssl,domain,in);			
					}
					else if (sel==1){
						send_email(UID,UPD,FROM,SUBJ,MSG,domain,ssl,RID_rep,opt);	
					}					
					else if (sel==2){
						printf("\nLoading Inbox...\n");
						check_mailbox(UID,UPD,ssl,emails,n_mes);
						inbox_menu(n_mes,emails,ssl,SUBJ,FROM,RID_rep,opt,MSG,UID,UPD);
					}
					else if (sel==3){
						printf("\nDeleting %d...\n",del);
						email_delete(UID,UPD,ssl,emails,del);
						printf("\nEmail %d deleted!\n\n",del);						
						//check_mailbox(UID,UPD,ssl,emails,n_mes);
						//printf("\nIN?\n");
						//inbox_menu(n_mes,emails,ssl,SUBJ,FROM,RID_rep,opt,MSG,UID,UPD);
						
					}	
				}
			}			 
		}
	}
}


void quit(){
	printf("Quiting...\n");
	exit(0);
}

int main(){

	email emails[Inbox_Size];
	int n_mes,in=0;
	char opt[10]="";
	char RID_rep[30]="";
	char TEMP[30]="";

	char UID[30];
	char UPD[30];
	char FROM[30];
	char SUBJ[100];
	char MSG[1000];
	clear_strings(UID,UPD,FROM,SUBJ,MSG);
	
	printf("\n\nWelcome to our EMAIL_CLIENT!\n\n");

	char choice[10],choice2[10];
	
	main_page(choice);
	printf("\nChoice was %d\n",atoi(choice));
	while(atoi(choice) != 0)
	{
		switch(atoi(choice))
		{
			case 1:
				do{
					clear_strings(UID,UPD,FROM,SUBJ,MSG);
					login_process(UID,UPD,FROM,"gmail.com");
					ssl_commands(UID,UPD,FROM,SUBJ,MSG,"smtp.gmail.com","gmail.com",465,0,emails,&n_mes,RID_rep,opt,&in,0);
				}
				while(in!=1);
				printf("\n>> Login Successful!<<\n");
				login_page(UID,choice2);
				while(atoi(choice2) != 0)
				{
					switch(atoi(choice2))
					{
						case 1:
							printf("\n>> Send email Operation! <<\n");
							printf("\nUID: %s\n",UID);
							printf("\nUPD: %s\n",UPD);
						
							printf("\nEnter the Subject of the email: ");
							getchar();									
							fgets(SUBJ, sizeof(SUBJ), stdin);
											
							printf("\nEnter the text of the email: ");	
							fgets(MSG, sizeof(MSG), stdin);

							ssl_commands(UID,UPD,FROM,SUBJ,MSG,"smtp.gmail.com","gmail.com",465,1,emails,&n_mes,RID_rep,opt,&in,0);
							printf("\nEmail send successfully!\n");									
							break;
						case 2:
							memset(SUBJ,0,sizeof(SUBJ));
							memset(MSG,0,sizeof(MSG));
							memset(RID_rep,0,sizeof(RID_rep));

							ssl_commands(UID,UPD,FROM,SUBJ,MSG,"pop.gmail.com","gmail.com",995,2,emails,&n_mes,RID_rep,opt,&in,0);
							if(opt[0]=='r'){
								printf("\nEnter the text of the email: ");	
								getchar();								
								fgets(MSG, sizeof(MSG), stdin);
		  						ssl_commands(UID,UPD,FROM,SUBJ,MSG,"smtp.gmail.com","gmail.com",465,1,emails,&n_mes,RID_rep,opt,&in,0);							
								printf("\nEmail replied successfully!\n");
								memset(opt,0,sizeof(opt));								
							}

							if(opt[0]=='f'){
								printf("\nEnter the recipient of the email: ");	
								getchar();								
								fgets(RID_rep, sizeof(RID_rep), stdin);
								strtok(RID_rep, "\n");
								strcat(TEMP, "<");
								strcat(TEMP, RID_rep);
								strcat(TEMP, ">");						
		  						ssl_commands(UID,UPD,FROM,SUBJ,MSG,"smtp.gmail.com","gmail.com",465,1,emails, &n_mes, TEMP, opt,&in,0);							
								printf("\nEmail forwarded successfully!\n");
								memset(opt,0,sizeof(opt));								
							}
							while(opt[0]=='d'){
								printf("\nHey!\n");
								ssl_commands(UID,UPD,FROM,SUBJ,MSG,"pop.gmail.com","gmail.com",995,2,emails,&n_mes,RID_rep,opt,&in,0);	
							}
							
							break;	
						case 3:
							clear_strings(UID,UPD,FROM,SUBJ,MSG);
							printf("\nUser just signed out!\n");							
							break;					

						default:
							clear_strings(UID,UPD,FROM,SUBJ,MSG);	
							printf("\nAn invalid choice has slipped through.\nPlease try again\n\n");
					}
					if(atoi(choice2)==3)
						break;				
					login_page(UID,choice2);								
				}
				break;

			case 2:
				quit();
				break;
			
			default: 
				printf("An invalid choice has slipped through.\nPlease try again.\n\n");
		}
		main_page(choice);
	}
	return 0;
}									
