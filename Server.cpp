#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <cstdio>
#include <stdio.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <string>
#include <clocale>


#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")




struct client_ctx
{
	int socket;
	CHAR buf_recv[512];
	CHAR buf_send[512];
	unsigned int sz_recv;
	unsigned int sz_send_total;
	unsigned int sz_send;

	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;

	HCRYPTPROV DescriptorCSP;
	HCRYPTKEY DescriptorKey;
	HCRYPTKEY DescriptorKey_open;

	bool key;

	DWORD flags_recv;
};

struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr,
				&remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			g_ctxs[i].key = false;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct
		sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	//if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	if (g_ctxs[idx].sz_recv == (int)(i))
	{
		*len = (int)(i);
		return 1;
	}
	return 0;
}

//HCRYPTPROV DescriptorCSP = 0;
//HCRYPTKEY DescriptorKey = 0;
//HCRYPTKEY DescriptorKey_open = 0;

void crypt_keys_make(int idx)
{
	if (!CryptAcquireContextW(&g_ctxs[idx].DescriptorCSP, NULL, NULL, PROV_RSA_FULL, NULL))
	{
		if (!CryptAcquireContextW(&g_ctxs[idx].DescriptorCSP, NULL, NULL, PROV_RSA_FULL, (CRYPT_NEWKEYSET)))

			printf("ERROR, %x", GetLastError());

	}
	if (CryptGenKey(g_ctxs[idx].DescriptorCSP, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].DescriptorKey) == 0)//создаём сеансовый ключ
		printf("ERROR, %x", GetLastError());
	int i = 255;
	for (; i >= 0 && g_ctxs[idx].buf_recv[i] == 0;)
		i--;
	unsigned int len = (unsigned char)g_ctxs[idx].buf_recv[i];
	g_ctxs[idx].buf_recv[i] = 0;
	if (!CryptImportKey(g_ctxs[idx].DescriptorCSP, (BYTE*)g_ctxs[idx].buf_recv, len, 0, 0, &g_ctxs[idx].DescriptorKey_open))//получаем открытый ключ
		printf("ERROR, %x", GetLastError());
	DWORD lenExp = 512;
	if (!CryptExportKey(g_ctxs[idx].DescriptorKey, g_ctxs[idx].DescriptorKey_open, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[idx].buf_send, &lenExp))//шифруем сеансовый ключ открытым
		printf("ERROR, %x", GetLastError());
	g_ctxs[idx].buf_send[lenExp] = lenExp;
	g_ctxs[idx].sz_send_total = lenExp + 1;
}

int number_of_digits(DWORD number)
{
	int digits = 0;
	while (number != 0)
	{
		number /= 10;
		digits += 1;
	}
	return digits;
}

void itoa_mod(unsigned long long num, char * str, int index, int radius)
{
	int r_d = radius;
	unsigned long long del = 1;
	while (r_d > 0)
	{
		del *= 10;
		r_d--;
	}
	del /= 10;
	while (radius > 0)
	{
		str[index] = (char)((num / del) + 48);
		num %= del;
		del /= 10;
		index++;
		radius--;
	}
}

char* search_name(char *p)
{
	int i = 0;
	while (p[i] != L'\\' && p[i] != '\0')
	{
		i++;
	}
	i++;
	return &p[i];
}

HKEY Search_key(char str[], int &size)
{
	switch (str[5])
	{
	case 'L':
	{
		size = 19;
		return HKEY_LOCAL_MACHINE;
	}
	case 'U':
	{
		size = 11;
		return HKEY_USERS;
	}
	case 'C':
	{
		switch (str[13])
		{
		case 'R':
		{
			size = 18;
			return HKEY_CLASSES_ROOT;
		}
		case 'C':
		{
			size = 20;
			return HKEY_CURRENT_CONFIG;
		}
		case 'U':
		{
			size = 18;
			return HKEY_CURRENT_USER;
		}
		default: return 0;
		}
	}
	default: return 0;
	}
}

bool system_information(int idx, int number, const char * str)
{
	int index = 0;
	int count = 0;
	char disks[26][3] = { 0 };
	switch (number)
	{
	case 1:
	{
		OSVERSIONINFOEX osvi;
		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		GetVersionEx((LPOSVERSIONINFOA)&osvi);
		g_ctxs[idx].buf_send[0] = osvi.dwMajorVersion;
		g_ctxs[idx].buf_send[1] = osvi.dwMinorVersion;
		g_ctxs[idx].buf_send[2] = '\0';
		break;
	}
	case 2:
	{
		SYSTEMTIME sm;
		GetSystemTime(&sm);
		index = 0;
		g_ctxs[idx].buf_send[index++] = (char)(sm.wDay);
		g_ctxs[idx].buf_send[index++] = '.';
		g_ctxs[idx].buf_send[index++] = (char)(sm.wMonth);
		g_ctxs[idx].buf_send[index++] = '.';

		_itoa(sm.wYear, &g_ctxs[idx].buf_send[index++], 10);
		index += 3;
		g_ctxs[idx].buf_send[index++] = ' ';

		g_ctxs[idx].buf_send[index++] = (char)(sm.wHour + 3);
		g_ctxs[idx].buf_send[index++] = ':';
		g_ctxs[idx].buf_send[index++] = (char)(sm.wMinute);
		g_ctxs[idx].buf_send[index++] = ':';
		g_ctxs[idx].buf_send[index++] = (char)(sm.wSecond);
		g_ctxs[idx].buf_send[index++] = '\0';


		//sm.wHour += 3;
		//sm.wHour %= 24;

		break;
	}
	case 3:
	{

		int msec = GetTickCount();
		memcpy(g_ctxs[idx].buf_send, &msec, 4);
		g_ctxs[idx].buf_send[4] = '\0';
		break;
	}
	case 4:
	{
		MEMORYSTATUS stat;
		GlobalMemoryStatus(&stat);
		index = 0;
		int radius = number_of_digits(stat.dwMemoryLoad);
		itoa_mod(stat.dwMemoryLoad, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwMemoryLoad, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';
		radius = number_of_digits(stat.dwTotalPhys);
		itoa_mod(stat.dwTotalPhys, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwTotalPhys, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';

		radius = number_of_digits(stat.dwAvailPhys);
		itoa_mod(stat.dwAvailPhys, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwAvailPhys, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';

		radius = number_of_digits(stat.dwTotalPageFile);
		itoa_mod(stat.dwTotalPageFile, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwTotalPageFile, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';

		radius = number_of_digits(stat.dwAvailPageFile);
		itoa_mod(stat.dwAvailPageFile, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwAvailPageFile, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';

		radius = number_of_digits(stat.dwTotalVirtual);
		itoa_mod(stat.dwTotalVirtual, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwTotalVirtual, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '.';

		radius = number_of_digits(stat.dwAvailVirtual);
		itoa_mod(stat.dwAvailVirtual, g_ctxs[idx].buf_send, index, radius);
		//_itoa(stat.dwAvailVirtual, &g_ctxs[idx].buf_send[index], 10);
		index += radius;
		g_ctxs[idx].buf_send[index++] = '\0';
		break;
	}
	case 5:
	{
		DWORD dr = GetLogicalDrives();
		index = 0;
		count = 0;
		for (int i = 0; i < 26; i++)
		{
			int n = ((dr >> i) & 0x00000001);
			if (n == 1)
			{
				disks[count][0] = char(65 + i);
				disks[count][1] = ':';
				g_ctxs[idx].buf_send[index++] = disks[count][0];
				g_ctxs[idx].buf_send[index++] = (char)(GetDriveTypeA(disks[count]));
				//g_ctxs[idx].buf_send[index++] = '.';
				count++;
			}
		}
		g_ctxs[idx].buf_send[index] = '\0';
		break;
	}

	case 6:
	{
		DWORD dr = GetLogicalDrives();
		index = 0;
		count = 0;
		for (int i = 0; i < 26; i++)
		{
			int n = ((dr >> i) & 0x00000001);
			if (n == 1)
			{
				disks[count][0] = char(65 + i);
				disks[count][1] = ':';
				if (GetDriveTypeA(disks[count]) == DRIVE_FIXED)
				{
					UINT s, b, f, c;

					GetDiskFreeSpaceA(disks[count], (LPDWORD)&s, (LPDWORD)&b, (LPDWORD)&f, (LPDWORD)&c);
					//unsigned long long freeSpace = f * s * b / 1024 / 1024 / 1024;
					g_ctxs[idx].buf_send[index++] = disks[count][0];
					int radius = number_of_digits(f);
					itoa_mod(f, g_ctxs[idx].buf_send, index, radius);
					index += radius;
					sprintf(&g_ctxs[idx].buf_send[index++], ".");

					radius = number_of_digits(s);
					itoa_mod(s, g_ctxs[idx].buf_send, index, radius);
					index += radius;
					sprintf(&g_ctxs[idx].buf_send[index++], ".");

					radius = number_of_digits(b);
					itoa_mod(b, g_ctxs[idx].buf_send, index, radius);
					index += radius;
					sprintf(&g_ctxs[idx].buf_send[index++], ".");
					/*
					sprintf(&g_ctxs[idx].buf_send[index], "%llu.", freeSpace);
					index = strlen(g_ctxs[idx].buf_send);*/
				}
				count++;
			}
		}
		g_ctxs[idx].buf_send[index] = '\0';
		break;
	}
	case 7:
	{
		int sDword = sizeof(DWORD);
		int sMask = sizeof(ACCESS_MASK);
		char path[500] = { 0 };
		int i = 0;
		for (i = 0; i < (strlen(g_ctxs[idx].buf_recv) - 1); i++)
			path[i] = g_ctxs[idx].buf_recv[i + 1];
		path[i] = '\0';

		int size = 0;
		HKEY key = Search_key(path, size);

		PACL a;
		PSECURITY_DESCRIPTOR pSD;
		if (key == 0)
		{
			if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
			{
				g_ctxs[idx].buf_send[0] = '0';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
		}
		else {
			HKEY phkResult = (HKEY)malloc(sizeof(HKEY));
			char *keyName = search_name(path);
			if (RegOpenKeyA(key, keyName, &phkResult) != ERROR_SUCCESS)
			{

				g_ctxs[idx].buf_send[0] = '1';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
			if (GetSecurityInfo(phkResult, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
			{
				g_ctxs[idx].buf_send[0] = '0';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
		}

		ACL_REVISION_INFORMATION *buf = (ACL_REVISION_INFORMATION*)malloc(sizeof(ACL_REVISION_INFORMATION));
		GetAclInformation(a, buf, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);
		LPVOID AceInfo;
		for (int i = 0; i < a->AceCount; i++)
		{
			if (GetAce(a, i, &AceInfo) == 0)
			{
				g_ctxs[idx].buf_send[0] = '2';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
			ACCESS_ALLOWED_ACE *pACE = (ACCESS_ALLOWED_ACE*)AceInfo;//pACE-&gt; Header.AceType(BYTE); name; pACE - &gt; SidStart(DWORD); pACE - &gt; Mask(DWORD)
			PSID pSID;
			pSID = (PSID)(&(pACE->SidStart));
			wchar_t name[500] = { 0 }, Domain[500] = { 0 };
			unsigned int LenName = 500, LenDom = 500;
			SID_NAME_USE Type;
			if (LookupAccountSidW(NULL, pSID, (LPWSTR)name, (LPDWORD)&LenName, (LPWSTR)Domain, (LPDWORD)&LenDom, &Type) != 0)//меняются
			{
				itoa(pACE->SidStart, &g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], 10);
				count = strlen(g_ctxs[idx].buf_send);
				g_ctxs[idx].buf_send[count] = '_';
				for (int i = 0; i < LenName; i++)
				{
					sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], "_");
					sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], "%i", name[i]);
				}
				count = strlen(g_ctxs[idx].buf_send);
				g_ctxs[idx].buf_send[count] = '\n';
				itoa(pACE->Header.AceType, &g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], 10);
				count = strlen(g_ctxs[idx].buf_send);
				g_ctxs[idx].buf_send[count] = '_';
				itoa(pACE->Mask, &g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], 10);
				count = strlen(g_ctxs[idx].buf_send);
				g_ctxs[idx].buf_send[count] = '_';
				count++;
				g_ctxs[idx].buf_send[count] = '\t';
				count++;
			}
		}
		g_ctxs[idx].buf_send[count] = '\r';
		break;
	}
	case 8:
	{
		wchar_t path[500] = { 0 };
		int i = 0;
		for (i = 0; i < (strlen(g_ctxs[idx].buf_recv) - 1); i++)
			path[i] = (wchar_t)g_ctxs[idx].buf_recv[i + 1];
		path[i] = L'\0';
		PSID pOwnerSid = 0;
		PSECURITY_DESCRIPTOR pSD;
		if (path[1] == L':')
		{
			if (GetNamedSecurityInfoW((LPCWSTR)(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
			{
				g_ctxs[idx].buf_send[0] = '0';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
		}
		else
		{
			HKEY phkResult = (HKEY)malloc(sizeof(HKEY));
			int size = 0;
			HKEY key = Search_key(&g_ctxs[idx].buf_recv[1], size);
			char *keyName = search_name(&g_ctxs[idx].buf_recv[1]);
			if (RegOpenKeyA(key, keyName, &phkResult) != ERROR_SUCCESS)
			{

				g_ctxs[idx].buf_send[0] = '1';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
			if (GetSecurityInfo(phkResult, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
			{
				g_ctxs[idx].buf_send[0] = '0';
				g_ctxs[idx].buf_send[1] = '\0';
				break;
			}
		}

		if (pOwnerSid == NULL)
		{

			g_ctxs[idx].buf_send[0] = '3';
			g_ctxs[idx].buf_send[1] = '\0';
			break;
		}
		wchar_t name[500] = { 0 }, Domain[500] = { 0 };
		unsigned int LenName = 500, LenDom = 500;
		SID_NAME_USE SidName;
		DWORD SID;
		memcpy(&SID, pOwnerSid, sizeof(PSID));
		itoa(SID, g_ctxs[idx].buf_send, 10);
		count = strlen(g_ctxs[idx].buf_send);
		g_ctxs[idx].buf_send[count] = '\t';
		if (LookupAccountSidW(NULL, pOwnerSid, name, (LPDWORD)&LenName, Domain, (LPDWORD)&LenDom, &SidName) == 0)
		{
			g_ctxs[idx].buf_send[0] = '4';
			g_ctxs[idx].buf_send[1] = '\0';
			break;

		}
		for (int i = 0; i < LenName; i++)
		{
			sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], "_");
			sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], "%i", name[i]);
		}


		break;
	}
	default:
		return false;
	}

	return true;
}


void io_serv(short port)
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return;
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// Старт операции принятия подключения.


	schedule_accept();


	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. 
				// Ключ key - индекс вмассиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key,
							&g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						// Если строка полностью пришла, то сформировать ответ и начать его отправлять
						/*sprintf(g_ctxs[key].buf_send, "You string length: %d\n", len);
						g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);
						g_ctxs[key].sz_send = 0;
						schedule_write(key);*/
						if (!g_ctxs[key].key)
						{
							crypt_keys_make(key);
							g_ctxs[key].key = true;
						}
						else
						{
							DWORD count = 0;
							count = g_ctxs[key].sz_recv;
							if (!CryptDecrypt(g_ctxs[key].DescriptorKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[key].buf_recv, (DWORD*)&count))
								printf("ERROR, %x", GetLastError());

							if (strlen(g_ctxs[key].buf_recv) < 2)
							{
								bool fl = true;
								switch (g_ctxs[key].buf_recv[0])
								{
								case '1': fl = system_information(key, 1, "");
									break;
								case '2': fl = system_information(key, 2, "");
									break;
								case '3': fl = system_information(key, 3, "");
									break;
								case '4': fl = system_information(key, 4, "");
									break;
								case '5': fl = system_information(key, 5, "");
									break;
								case '6': fl = system_information(key, 6, "");
									break;
								}
							}
							else
							{
								bool fl = true;
								char path[512];
								int index = 0;
								while (g_ctxs[key].buf_recv[index + 1] != '\0')
								{
									path[index] = g_ctxs[key].buf_recv[index + 1];
									index++;
								}
								path[index] = '\0';
								switch (g_ctxs[key].buf_recv[0])
								{
								case '7': fl = system_information(key, 7, path);
									break;
								case '8': fl = system_information(key, 8, path);
									break;
								}
							}


							//sprintf(g_ctxs[key].buf_send, "length: %d\n", len);
							count = strlen(g_ctxs[key].buf_send);
							if (!CryptEncrypt(g_ctxs[key].DescriptorKey, NULL, TRUE, NULL, (BYTE*)g_ctxs[key].buf_send, (DWORD*)&count, 512))
								printf("ERROR, %x", GetLastError());
							g_ctxs[key].sz_send_total = count;


							//g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);

							g_ctxs[key].sz_send = 0;
							memset(g_ctxs[key].buf_recv, 0, 512);
						}
						schedule_write(key);
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						//CancelIo((HANDLE)g_ctxs[key].socket);
						//PostQueuedCompletionStatus(g_io_port, 0, key,
						//	&g_ctxs[key].overlap_cancel);
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, 512);
						g_ctxs[key].sz_send = 0;
						memset(g_ctxs[key].buf_recv, 0, 512);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket); memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
		}
	}
}

int main(/*int argc, char * argv[]*/)
{
	/*if (argc != 2)
	{
		printf("Error: Invalid port.\n");
		return 0;
	}*/
	short port = 9000;
	io_serv(port);
	return 0;
}