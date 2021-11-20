#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else // LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include<iostream>
#include <string.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include<fcntl.h>
#include<io.h>
#pragma warning (disable : 4996)
//#pragma comment(lib, "mswsock.lib")
using namespace std;

const int cMax_Server = 10;

struct server
{
	HCRYPTPROV DescriptorCSP;
	HCRYPTKEY DescriptorKey;
	HCRYPTKEY DescriptorKey_session;
	HCRYPTKEY hPublicKey, hPrivateKey;
	int s;
	struct sockaddr_in addr;
};

server servers[cMax_Server];
int count_server = 0;





int init()
{
#ifdef _WIN32
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
#else
	return 1;
#endif
}

void deinit()
{
#ifdef _WIN32
	WSACleanup();
#else
	// Äëÿ äðóãèõ ÎÑ äåéñòâèé íå òðåáóåòñÿ
#endif
}

int sock_err(const char* function, int s)
{
	int err;
#ifdef _WIN32
	err = WSAGetLastError();
#else
	err = errno;
#endif
	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

int connect_time(int s, struct sockaddr_in addr)
{
	int amount = 0;
	while (1)
	{
		fprintf(stdout, "%i try for connect\n", (amount + 1));
		int tryy = connect(s, (struct sockaddr*) &addr, sizeof(addr));
		if (tryy == 0)
			return 0;
		else
		{
			fprintf(stdout, "%i time failed to connect to server\n", (amount + 1));
			Sleep(1);
		}
		if (amount == 9) return -1;
		amount++;
	}
}

void s_close(int s)
{
	closesocket(s);
}


int CryptConnect(int s, sockaddr_in addr, int count_server)
{
	if (!CryptAcquireContextW(&servers[count_server].DescriptorCSP, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&servers[count_server].DescriptorCSP, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			printf("ERROR, %x", GetLastError());
	}
	if (CryptGenKey(servers[count_server].DescriptorCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &servers[count_server].DescriptorKey) == 0)
	{
		printf("ERROR, %x", GetLastError());
	}
	if (!CryptGetUserKey(servers[count_server].DescriptorCSP, AT_KEYEXCHANGE, &servers[count_server].hPublicKey))
	{
		printf("CryptGetUserKey ERROR\n");
	}
	if (!CryptGetUserKey(servers[count_server].DescriptorCSP, AT_KEYEXCHANGE, &servers[count_server].hPrivateKey))
	{
		printf("CryptGetUserKey ERROR\n");
	}
	char ExpBuf[512] = { 0 };
	DWORD len = 512;
	if (!CryptExportKey(servers[count_server].hPublicKey, 0, PUBLICKEYBLOB, NULL, (BYTE*)ExpBuf, &len))
	{
		printf("ERROR, %x", GetLastError());
	}
	int i = 255;
	for (; i >= 0 && ExpBuf[i] == 0;)
		i--;
	int l = i + 1;
	ExpBuf[l] = l;
	if (send(s, ExpBuf, (l + 1), 0) < 0)
		sock_err("send", s);
	char buffer[512] = { 0 };
	if (recv(s, buffer, 512, 0) < 0)
		sock_err("receive", s);
	i = 255;
	for (; i >= 0 && buffer[i] == 0;)
		i--;
	unsigned int dli = (unsigned char)buffer[i];
	buffer[i] = 0;
	if (!CryptImportKey(servers[count_server].DescriptorCSP, (BYTE *)buffer, dli, servers[count_server].hPrivateKey, 0, &servers[count_server].DescriptorKey_session))
	{
		printf("ERROR, %x", GetLastError());
	}
	return s;
}

void help()
{
	printf("1) Type and v. OS\n");
	printf("2) Present time\n");
	printf("3) Time has passed since the launch of the Os\n");
	printf("4) Info about storage\n");
	printf("5) Types of attached disks\n");
	printf("6) Free space on local drives\n");
	printf("7) Permissions to the specified directory\n");
	printf("8) Owner of the specified directory\n");
	printf("9) Add server\n");
	printf("0) Change server\n");
	printf("\"exit\" to close the application\n");
}

char* SearchRights(ACCESS_MASK mask, char rights[])

{

	if (mask&DELETE)

	{

		strcat(rights, "Delete access");
		rights[13] = '\n';

	}

	if (mask&READ_CONTROL)

	{

		strcat(rights, "Read access to the owner, group");

		rights[strlen(rights)] = '\n';

	}

	if (mask&WRITE_DAC)

	{

		strcat(rights, "Write access to the DACL");

		rights[strlen(rights)] = '\n';

	}

	if (mask&WRITE_OWNER)

	{

		strcat(rights, "Write access to owner");

		rights[strlen(rights)] = '\n';

	}

	if (mask&SYNCHRONIZE)

	{

		strcat(rights, "Synchronize acces");

		rights[strlen(rights)] = '\n';

	}

	if (mask&MAXIMUM_ALLOWED)

	{

		strcat(rights, "Maximum allowed");

		rights[strlen(rights)] = '\n';

	}

	if (mask&GENERIC_ALL)

	{

		strcat(rights, "Generic all");

		rights[strlen(rights)] = '\n';

	}

	if (mask&GENERIC_EXECUTE)

	{

		strcat(rights, "Generic execute");

		rights[strlen(rights)] = '\n';

	}

	if (mask&GENERIC_WRITE)

	{

		strcat(rights, "Generic write");

		rights[strlen(rights)] = '\n';

	}

	if (mask&GENERIC_READ)

	{

		strcat(rights, "Generic read");

		rights[strlen(rights)] = '\n';

	}

	rights[strlen(rights)] = '\0';

	return rights;

}


const char * TypeAce(BYTE t)

{

	switch (t)

	{

	case(ACCESS_ALLOWED_ACE_TYPE):

		return "ACCESS_ALLOWED_ACE_TYPE";

	case(ACCESS_ALLOWED_CALLBACK_ACE_TYPE):

		return "ACCESS_ALLOWED_CALLBACK_ACE_TYPE";

	case(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE):

		return "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE";

	case(ACCESS_ALLOWED_COMPOUND_ACE_TYPE):

		return "ACCESS_ALLOWED_COMPOUND_ACE_TYPE";

	case(ACCESS_ALLOWED_OBJECT_ACE_TYPE):

		return "ACCESS_ALLOWED_OBJECT_ACE_TYPE";

	case(ACCESS_DENIED_ACE_TYPE):

		return "ACCESS_DENIED_ACE_TYPE";

	case(ACCESS_DENIED_CALLBACK_ACE_TYPE):

		return "ACCESS_DENIED_CALLBACK_ACE_TYPE";

	case(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE):

		return "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE";

	case(ACCESS_DENIED_OBJECT_ACE_TYPE):

		return "ACCESS_DENIED_OBJECT_ACE_TYPE";

	case(ACCESS_MAX_MS_ACE_TYPE):
		return "ACCESS_MAX_MS_ACE_TYPE";

	case(ACCESS_MAX_MS_V2_ACE_TYPE):

		return "ACCESS_MAX_MS_V2_ACE_TYPE";

	case(SYSTEM_ALARM_CALLBACK_ACE_TYPE):

		return "SYSTEM_ALARM_CALLBACK_ACE_TYPE";

	case(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE):

		return "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE";

	case(SYSTEM_AUDIT_ACE_TYPE):

		return "SYSTEM_AUDIT_ACE_TYPE";

	default:

		return "Error";

		break;

	}

}

void printf_error(char symbol)
{
	switch (symbol)
	{
	case '0': printf("GetSecError\n");
		break;
	case '1': printf("RegOpeError\n");
		break;
	case '2': printf("GetAceError\n");
		break;
	case '3': printf("OwnSidError\n");
		break;
	case '4': printf("LokupAError\n");
		break;
	}
}


int add_server(short port, char * arg)
{
	if (count_server >= cMax_Server)
		return -1;
	servers[count_server].s = socket(AF_INET, SOCK_STREAM, 0);
	if (servers[count_server].s < 0)
		return sock_err("socket", servers[count_server].s);
	memset(&servers[count_server].addr, 0, sizeof(servers[count_server].addr));
	servers[count_server].addr.sin_family = AF_INET;
	servers[count_server].addr.sin_port = htons(port);
	servers[count_server].addr.sin_addr.s_addr = inet_addr(arg);
	if (connect_time(servers[count_server].s, servers[count_server].addr) != 0)
	{
		s_close(servers[count_server].s);
		return sock_err("connect", servers[count_server].s);
	}
	servers[count_server].s = CryptConnect(servers[count_server].s, servers[count_server].addr, count_server);
	count_server++;
	return count_server-1;
}

int main()
{
	char argv[32];
	printf("Enter IP_addr:port\n");
	fgets(argv, 32, stdin);
	char port_tmp[5];
	bool flag = 0;

	for (int i = 0; i < strlen(argv); i++)
	{
		if (argv[i] == ':')
		{
			flag = 1;
			argv[i] = '\0';
			i++;
			int j = 0;
			for (j = 0; argv[i] != '\n'; j++, i++)
				port_tmp[j] = argv[i];
			port_tmp[j] = '\0';
			break;
		}
	}

	if (flag == 0)
		return sock_err("finding the port", 0);
	short port = (short)atoi(port_tmp);
	init();
	int index_server = add_server(port, argv);
	memset(argv, 0, 32);
	int amount_mes = 0;
	FILE *file = fopen("info.txt", "a +");
	char choice[512];
	char message[512];
	char return_message[512];
	help();
	printf("Server %d:\nWhat information about the system do you want to khow? \n", index_server+1);
	fgets(choice, 512, stdin);
	while (strcmp(choice, "exit\n") != 0)
	{
		int index = 0;
		int length = 0;
		unsigned int num = 0;
		int ticks = 0;
		int year_f = 0;
		int recv_count = 0;
		fprintf(file, "Server %d", index_server + 1);
		switch (choice[0])
		{
		case '1':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '1';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			if (recv(servers[index_server].s, return_message, 512, 0) < 0)
				return sock_err("receive", servers[index_server].s);
			index = 255;
			while (index >= 0 && return_message[index] == 0)
				index--;
			length = index + 1;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());
			fwrite("Type and v. OS\n", sizeof(char), strlen("Type and v. OS\n"), file);
			
			if (return_message[0] == 4)
			{
				switch (return_message[1])
				{
				case 0:
					printf("Windows 95\n");
					fwrite("Windows 95\n", sizeof(char), strlen("Windows 95\n"), file);
					break;
				case 10:
					printf("Windows 98\n");
					fwrite("Windows 98\n", sizeof(char), strlen("Windows 98\n"), file);
					break;
				case 90:
					printf("WindowsMe\n");
					fwrite("WindowsMe\n", sizeof(char), strlen("WindowsMe\n"), file);
					break;
				default:
					printf("Failed to determine OS\n");
					fwrite("Failed to determine OS\n", sizeof(char), strlen("Failed to determine OS\n"), file);
					break;
				}
			}
			else if (return_message[0] == 5)
			{
				switch (return_message[1])
				{
				case 0:
					printf("Windows 2000\n");
					fwrite("Windows 2000\n", sizeof(char), strlen("Windows 2000\n"), file);
					break;
				case 1:
					printf("Windows XP\n");
					fwrite("Windows XP\n", sizeof(char), strlen("Windows XP\n"), file);
					break;
				case 2:
					printf("Windows 2003\n");
					fwrite("Windows 2003\n", sizeof(char), strlen("Windows 2003\n"), file);
					break;
				default:
					printf("Failed to determine OS\n");
					fwrite("Failed to determine OS\n", sizeof(char), strlen("Failed to determine OS\n"), file);
					break;
				}
			}
			else if (return_message[0] == 6)
			{
				switch (return_message[1])
				{
				case 0:
					printf("Windows Vista\n");
					fwrite("Windows Vista\n", sizeof(char), strlen("Windows Vista\n"), file);
					break;
				case 1:
					printf("Windows 7\n");
					fwrite("Windows 7\n", sizeof(char), strlen("Windows 7\n"), file);
					break;
				case 2:
					printf("Windows 10\n");
					fwrite("Windows 10\n", sizeof(char), strlen("Windows 10\n"), file);
					break;
				case 3:
					printf("Windows 8\n");
					fwrite("Windows 8\n", sizeof(char), strlen("Windows 8\n"), file);
					break;
				default:
					printf("Failed to determine OS\n");
					fwrite("Failed to determine OS\n", sizeof(char), strlen("Failed to determine OS\n"), file);
					break;
				}
			}
			else
			{
				printf("Failed to determine OS\n");
				fwrite("Failed to determine OS\n", sizeof(char), strlen("Failed to determine OS\n"), file);
			}
			break;
		case '2':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '2';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());

			index = 0;

			fwrite("Present time\n", sizeof(char), strlen("Present time\n"), file);
			

			for (; index < length - 1; index++)
			{
				if (year_f < 2)
				{
					if (return_message[index] != '.')
					{
						num = (int)(return_message[index]);
						if (num < 10)
						{
							printf("0%d.", num);
							fprintf(file, "0%d.", num);
						}
						else
						{
							printf("%d.", num);
							fprintf(file, "0%d.", num);
						}
						year_f++;
					}
				}
				else if (year_f == 2)
				{
					if (return_message[index] != '.')
					{
						num = 0;
						for (int i = 0; i < 4; i++)
						{
							num = (num * 10) + ((int)(return_message[index++]) - 48);
						}
						printf("%d ", num);
						fprintf(file, "%d ", num);
						year_f++;
					}
				}
				else if (year_f < 5)
				{
					if (return_message[index] != ':')
					{
						num = (int)(return_message[index]);
						if (num < 10)
						{
							printf("0%d:", num);
							fprintf(file, "0%d:", num);
						}
						else
						{
							printf("%d:", num);
							fprintf(file, "%d:", num);
						}
						year_f++;
					}
				}
				else
				{
					num = (int)(return_message[index]);
					if (num < 10)
					{
						printf("0%d\n", num);
						fprintf(file, "0%d\n", num);
					}
					else
					{
						printf("%d\n", num);
						fprintf(file, "%d\n", num);
					}
				}
			}

			break;
		case '3':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '3';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
				//index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());
			return_message[length] = '\0';
			ticks = 0;
			memcpy(&ticks, return_message, 4);
			fwrite("Time has passed since the launch of the Os\n", sizeof(char), strlen("Time has passed since the launch of the Os\n"), file);
			printf("hours = %i minutes =  %i seconds =  %i\n", (ticks / (1000 * 60 * 60)),
				(ticks / (1000 * 60) - (ticks / (1000 * 60 * 60)) * 60), ((ticks / 1000) - ((ticks / (1000 * 60 * 60)) *
					60 * 60) - (ticks / (1000 * 60) - (ticks / (1000 * 60 * 60)) * 60) * 60));
			fprintf(file, "hours = %i minutes =  %i seconds =  %i\n", (ticks / (1000 * 60 * 60)),
				(ticks / (1000 * 60) - (ticks / (1000 * 60 * 60)) * 60), ((ticks / 1000) - ((ticks / (1000 * 60 * 60)) *
					60 * 60) - (ticks / (1000 * 60) - (ticks / (1000 * 60 * 60)) * 60) * 60));
			break;
		case '4':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '4';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());
			num = 0;
			index = 0;

			fwrite("Info about storage\n", sizeof(char), strlen("Info about storage\n"), file);
			
			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("Load: %lu%\n", num);
			fprintf(file, "Load: %lu%\n", num);
			num = 0;
			index++;

			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("TotalPhys: %lu bytes\n", num);
			fprintf(file, "TotalPhys: %lu bytes\n", num);
			num = 0;
			index++;

			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("AvailPhys: %lu bytes\n", num);
			fprintf(file, "AvailPhys: %lu bytes\n", num);
			num = 0;
			index++;

			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("TotalPageFile: %lu bytes\n", num);
			fprintf(file, "TotalPageFile: %lu bytes\n", num);
			num = 0;
			index++;

			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("AvailPageFile: %lu bytes\n", num);
			fprintf(file, "TotalPageFile: %lu bytes\n", num);
			num = 0;
			index++;

			while (return_message[index] != '.')
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("TotalVirtual: %lu bytes\n", num);
			fprintf(file, "TotalPageFile: %lu bytes\n", num);
			num = 0;
			index++;

			while (index < length)
			{
				num = (num * 10) + ((unsigned int)(return_message[index]) - 48);
				index++;
			}
			printf("AvailVirtual: %lu bytes\n", num);
			fprintf(file, "TotalPageFile: %lu bytes\n", num);
			break;
		case '5':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '5';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());
			index = 0;
			fwrite("Types of attached disks\n", sizeof(char), strlen("Types of attached disks\n"), file);
			
			while (return_message[index] != '\0' && index < length)
			{
				switch ((int)(return_message[index + 1]))
				{
				case 0:
					printf("%c - unknown\n", return_message[index]);
					fprintf(file, "%c - unknown\n", return_message[index]);
					break;
				case 1:
					printf("%c - root path is invalid\n", return_message[index]);
					fprintf(file, "%c - root path is invalid\n", return_message[index]);
					break;
				case 2:
					printf("%c - removable\n", return_message[index]);
					fprintf(file, "%c - removable\n", return_message[index]);
					break;
				case 3:
					printf("%c - fixed\n", return_message[index]);
					fprintf(file, "%c - fixed\n", return_message[index]);
					break;
				case 4:
					printf("%c - network\n", return_message[index]);
					fprintf(file, "%c - network\n", return_message[index]);
					break;
				case 5:
					printf("%c - CD-ROM\n", return_message[index]);
					fprintf(file, "%c - CD-ROM\n", return_message[index]);
					break;
				case 6:
					printf("%c - RAM\n", return_message[index]);
					fprintf(file, "%c - RAM\n", return_message[index]);
					break;
				default:
					break;
				}
				index += 2;
			}
			break;
		case '6':
			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '6';
			message[1] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());

			fwrite("Free space on local drives\n", sizeof(char), strlen("Free space on local drives\n"), file);
			for (int i = 0; i < length;)
			{
				printf("%c: ", return_message[i]);
				fprintf(file, "%c: ", return_message[i]);
				i++;
				unsigned int s = 0;
				while (return_message[i] != '.')
				{
					s = s * 10 + ((unsigned int)(return_message[i] - 48));
					i++;
				}
				i++;

				unsigned int b = 0;
				while (return_message[i] != '.')
				{
					b = b * 10 + ((unsigned int)(return_message[i] - 48));
					i++;
				}
				i++;

				unsigned int f = 0;
				while (return_message[i] != '.')
				{
					f = f * 10 + ((unsigned int)(return_message[i] - 48));
					i++;
				}
				i++;

				double freeSpace = (double)f * (double)s * (double)b / 1024.0 / 1024.0 / 1024.0;

				printf("%f GB\n", freeSpace);
				fprintf(file, "%f GB\n", freeSpace);
			}
			break;
		case '7':
		{
			memset(choice, 0, 512);
			printf("Enter path(C:\\1.txt): ");
			fgets(choice, 512, stdin);

			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '7';
			index = 1;
			for (int i = 0; choice[i] != '\n'; i++, index++)
			{
				message[index] = choice[i];
			}
			message[index] = '\0';
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());

			fwrite("Permissions to the specified directory\n", sizeof(char), strlen("Permissions to the specified directory\n"), file);
			

			if (length > 2)
			{
				int j = 0;
				int sAccess = sizeof(ACCESS_MASK);
				while (return_message[j] != '\r' && j < length - 1)
				{
					char temp[32] = { '\0' };
					int tempIdx = 0;
					while (return_message[j] != '_')
					{
						temp[tempIdx] = return_message[j];
						j++;
						tempIdx++;
					}
					j++;
					temp[tempIdx] = '\0';
					tempIdx = 0;
					printf("SID: %s\n", temp);
					fprintf(file, "SID: %s\n", temp);
					char name[512] = { '\0' };
					int idx = 0;
					printf("Name: ");
					fprintf(file, "Name: ");
					wchar_t wname[100] = { 0 };
					for (int i = 0; return_message[j] != '\n'; i++)
					{
						j++;
						wname[i] = atoi(&return_message[j]);
						while (return_message[j] != '_' && return_message[j] != '\n')
							j++;
					}
					_setmode(_fileno(stdout), _O_U16TEXT);
					wprintf(wname);
					fwprintf(file, wname);
					_setmode(_fileno(stdout), _O_TEXT);
					printf("\n");
					fprintf(file, "\n");
					while (return_message[j] != '_')
					{
						temp[tempIdx] = return_message[j];
						j++;
						tempIdx++;
					}
					j++;
					temp[tempIdx] = '\0';
					BYTE ace = atoi(temp);
					memset(temp, '\0', tempIdx);
					tempIdx = 0;
					while (return_message[j] != '_')
					{
						temp[tempIdx] = return_message[j];
						j++;
						tempIdx++;
					}
					j++;
					temp[tempIdx] = '\0';
					ACCESS_MASK Mask = (ACCESS_MASK)atoi(temp);
					cout << "Type ACE: " << TypeAce((BYTE)ace) << endl;
					cout << "Rights: " << endl;
					fprintf(file, "Type ACE: ");
					fprintf(file, TypeAce((BYTE)ace));
					fprintf(file, "\nRights: ");
					int i = 0;
					unsigned int deg = 1;
					char rights[512] = { '\0' };
					SearchRights(Mask, rights);
					cout << rights << endl;
					fprintf(file, rights);
					j++;
				}
			}
			else
			{
				printf_error(return_message[0]);
			}
			break;
		}
		case '8':
			memset(choice, 0, 512);
			printf("Enter path(C:\\1.txt): ");
			fgets(choice, 512, stdin);

			memset(message, 0, 512);
			memset(return_message, 0, 512);
			message[0] = '8';
			index = 1;
			for (int i = 0; choice[i + 1] != '\0'; i++, index++)
			{
				message[index] = choice[i];
			}
			length = strlen(message);
			if (!CryptEncrypt(servers[index_server].DescriptorKey_session, 0, TRUE, 0, (BYTE*)message, (DWORD*)&length, 512))
				printf("ERROR, %x", GetLastError());
			if (send(servers[index_server].s, message, length, 0) < 0)
				return sock_err("send", servers[index_server].s);
			recv_count = recv(servers[index_server].s, return_message, 512, 0);
			if (recv_count < 0)
				return sock_err("receive", servers[index_server].s);
			//index = 255;
			//while (index >= 0 && return_message[index] == 0)
			//	index--;
			length = recv_count;
			if (!CryptDecrypt(servers[index_server].DescriptorKey_session, NULL, TRUE, NULL, (BYTE*)return_message, (DWORD*)&length))
				printf("ERROR, %x", GetLastError());
			fwrite("Owner of the specified directory\n", sizeof(char), strlen("Owner of the specified directory\n"), file);

			if (length > 2)
			{
				printf("SID of the owner : ");
				fprintf(file, "SID of the owner : ");
				int j = 0;
				for (; return_message[j] != '\t'; j++)
				{
					printf("%c", return_message[j]);
					fprintf(file, "%c", return_message[j]);
				}
				j++;
				printf("\n");
				fprintf(file, "\n");
				wchar_t name[100] = { 0 };
				for (int i = 0; return_message[j] != '\0'; i++)
				{
					j++;
					name[i] = atoi(&return_message[j]);
					while (return_message[j] != '_' && return_message[j] != '\0')
						j++;
				}
				printf("Name: ");
				fprintf(file, "Name: ");
				_setmode(_fileno(stdout), _O_U16TEXT);
				wprintf(name);
				fwprintf(file, name);
				_setmode(_fileno(stdout), _O_TEXT);
				printf("\n");
				fprintf(file, "\n");
				break;
			}
			else
			{
				printf_error(return_message[0]);
			}
			break;
		case '9':
		{
			printf("Enter IP_addr:port\n");
			fgets(argv, 32, stdin);
			port_tmp[5];
			flag = 0;
			for (int i = 0; i < strlen(argv); i++)
			{
				if (argv[i] == ':')
				{
					flag = 1;
					argv[i] = '\0';
					i++;
					int j = 0;
					for (j = 0; argv[i] != '\n'; j++, i++)
						port_tmp[j] = argv[i];
					port_tmp[j] = '\0';
					break;
				}
			}

			if (flag == 0)
				return sock_err("finding the port", 0);
			port = (short)atoi(port_tmp);
			int ccc = add_server(port, argv);
			if (ccc < 0)
			{
				printf("Too many servers\n");
			}
			else
			{
				index_server = ccc;
			}
			memset(argv, 0, 32);
			break;
		}
		case '0':
		{
			memset(choice, 0, 512);
			printf("Enter number of server: ");
			fgets(choice, 512, stdin);
			int chc = (int)atoi(choice);
			if ((chc-1) >= count_server)
			{
				printf("Error number\n");
			}
			else
			{
				index_server = (chc - 1);
			}
			memset(argv, 0, 32);
			break;
		}
		}



		memset(choice, 0, 512);
		printf("Server %d:\nWhat information about the system do you want to khow? \n", index_server + 1);
		fgets(choice, 512, stdin);
		amount_mes++;
	}



	return 0;
}