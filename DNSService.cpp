/*
Name: Phong Tran
Class: CSCE 463-500
*/

#include "DNSService.h"

//to detect jump loop
unordered_set<int> offsets;

DNSService::DNSService()
{
}

DNSService::~DNSService()
{
	closesocket(sock);
}

bool DNSService::setupSocket()
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET){
		printf("socket error %d\n", WSAGetLastError());
		return false;
	}

	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR){
		printf("socket error %d\n", WSAGetLastError());
		return false;
	}

	return true;
}

string DNSService::toRRType(USHORT t)
{
	switch (t){
	case DNS_A:
		return "A";
	case DNS_CNAME:
		return "CNAME";
	case DNS_NS:
		return "NS";
	case DNS_PTR:
		return "PTR";
	case DNS_HINFO:
		return "HINFO";
	case DNS_MX:
		return "MX";
	case DNS_AXFR:
		return "AXFR";
	default:
		return "ANY";
	}
}

//reverse ip and copy it into buf
void DNSService::reverseIp(char* buf, char* ip, int len)
{
	char* copyStr = new char[strlen(ip) + 1];
	Utils::myStrCopy(ip, copyStr, strlen(ip) + 1);

	stack<char*> st;
	char* ptr = copyStr;
	char* front = ptr;

	while (true){
		ptr = strchr(ptr, '.');

		if (ptr == NULL){
			st.push(front);
			break;
		}
		*ptr = 0;
		st.push(front);

		ptr++;
		front = ptr;
	}

	char* p = buf;
	while (!st.empty()){
		char* top = st.top();
		st.pop();

		Utils::myStrCopy(top, p, strlen(top));
		*(p + strlen(top)) = '.';
		p += strlen(top) + 1;
	}
	Utils::myStrCopy("in-addr.arpa\0", p, 13);

	delete[] copyStr;
}

//construct name for dns look up
void DNSService::makeDNSQuestion(char* buf, char* host)
{
	char* bufPtr = buf;
	char* hostPtr = host;
	char* front = hostPtr;

	while (true){
		hostPtr = strchr(hostPtr, '.');

		if (hostPtr == NULL){
			*bufPtr = strlen(front);
			Utils::myStrCopy(front, bufPtr + 1, strlen(front));
			bufPtr += strlen(front) + 1;
			break;
		}

		*bufPtr = hostPtr - front;
		Utils::myStrCopy(front, bufPtr + 1, hostPtr - front);

		bufPtr += hostPtr - front + 1;
		hostPtr++;
		front = hostPtr;
	}
	*bufPtr = 0;
}

//turn bits into ip string
string DNSService::toIP(unsigned char* ptr, int len)
{
	string result;
	unsigned char* srcPtr = ptr;

	for (int i = 0; i < len; i++){
		//missing character, return empty string
		if (*srcPtr == 0 && i < len - 1)
			return string();

		result += to_string((int)(*srcPtr));
		if (i != len - 1)
			result += ".";
		srcPtr++;
	}
	return result;
}

//turn bits into readable name
unsigned char* DNSService::resolveName(unsigned char* buf, unsigned char* name, char* response)
{
	int i = 0;
	unsigned int size = 0;

	while (true){
		if (i % 2 == 0){
			size = *name;
		}
		else {
			if (size >= 0xc0){
				if (name[1] == 0 && name[2] >= 0xcc){
					printf("  ++    invalid record: truncated jump offset\n");
					return NULL;
				}

				int offset = ((~(0xc0) & size) << 8) + name[1];
				if (offset < sizeof(DNSHeader)){
					printf("  ++    invalid record: jump into fixed header\n");
					return NULL;
				}
				if (offset >= bytes){
					printf("  ++    invalid record: jump beyond packet boundary\n");
					return NULL;
				}
				if (!Utils::isUnique(offsets, offset)){
					printf("  ++    invalid record: jump loop\n");
					return NULL;
				}

				name = (unsigned char*)((unsigned char*)response + offset);
				buf = resolveName(buf, name, response);
				if (buf == NULL)
					return NULL;
				break;
			}
			else {
				if (Utils::myStrCopy((char*)(name + 1), (char*)buf, size) < 0){
					printf("  ++    invalid record: truncated name\n");
					return NULL;
				}

				*(buf + size) = '.';
				buf += size + 1;
				name += size + 1;

				if (*(name + 1) == 0xcc){
					printf("  ++    invalid record: truncated name\n");
					return NULL;
				}
				if (*name == 0){
					*(--buf) = 0;
					break;
				}
			}
		}
		i++;
	}
	return buf;
}

bool DNSService::readQuestion(unsigned char*& content, ResourceRecord* resourceRecord, int n)
{
	int iteration = 0;

	while (iteration++ < n){
		unsigned char* name = content;
		unsigned char* properName = new unsigned char[MAX_DNS_SIZE];
		if (resolveName(properName, name, responseBuf) == NULL){
			delete[] properName;
			return false;
		}
		resourceRecord = (ResourceRecord*)(name + strlen((char*)name) + 1);

		printf("	%s type %d class %d\n", properName, ntohs(resourceRecord->rType), ntohs(resourceRecord->rClass));
		name += strlen((char*)name) + 5;	//skip the query header
		content = name;
		delete[] properName;
	}
	return true;
}

bool DNSService::readAnswer(unsigned char*& content, ResourceRecord* resourceRecord, int n)
{
	int iteration = 0;
	unsigned char* name;

	while (iteration++ < n){
		if (*content == 0){
			printf("  ++    invalid section: not enough records\n");
			return false;
		}

		//clear hash map for each record
		offsets.clear();
		name = content;
		unsigned char* properName = new unsigned char[MAX_DNS_SIZE];
		if (resolveName(properName, name, responseBuf) == NULL){
			delete[] properName;
			return false;
		}

		//find RR field
		while (*content < 0xc0 && *content != 0)
			content++;
		resourceRecord = (ResourceRecord*)(*content == 0 ? content + 1 : content + 2);

		//check for truncated RR header
		if ((char*)(&resourceRecord->rType) >= (char*)(bytes + responseBuf - 1)
			|| (char*)(&resourceRecord->rClass) >= (char*)(bytes + responseBuf - 1)
			|| (char*)(&resourceRecord->ttl) >= (char*)(bytes + responseBuf - 3)
			|| (char*)(&resourceRecord->rLength) >= (char*)(bytes + responseBuf - 1)){
			printf("  ++    invalid record: truncated fixed RR header\n");
			delete[] properName;
			return false;
		}

		string rType = toRRType(ntohs(resourceRecord->rType));
		USHORT rLength = ntohs(resourceRecord->rLength);

		if (rType == "PTR" || rType == "CNAME" || rType == "NS"){
			offsets.clear();
			unsigned char* dn = (unsigned char*)(&(resourceRecord->rLength) + 1);
			unsigned char* properDN = new unsigned char[MAX_DNS_SIZE];
			if (resolveName(properDN, dn, responseBuf) == NULL){
				delete[] properName;
				delete[] properDN;
				return false;
			}
			printf("	%s %s %s TTL = %d\n", properName, rType.c_str(), properDN, ntohl(resourceRecord->ttl));
			delete[] properDN;
		}
		else if (rType == "A"){
			string addr = toIP((unsigned char*)(&(resourceRecord->rLength) + 1), rLength);
			if (addr.empty()){
				printf("  ++    invalid record: value length beyond packet\n");
				delete[] properName;
				return false;
			}
			printf("	%s %s %s TTL = %d\n", properName, rType.c_str(), addr.c_str(), ntohl(resourceRecord->ttl));
		}

		if ((rLength + (char*)(&(resourceRecord->rLength) + 1)) > (char*)(bytes + responseBuf)){
			printf("  ++    invalid record: value length beyond packet\n");
			delete[] properName;
			return false;
		}

		content = rLength + (unsigned char*)(&(resourceRecord->rLength) + 1);
		delete[] properName;
	}
	return true;
}

//sends request and stores the answer
bool DNSService::query(char* host, char* dns)
{
	//print look up string
	printf("Look up	: %s\n", host);

	int size = strlen(host) + 2 + sizeof(DNSHeader) + sizeof(QueryHeader);
	DWORD ip = inet_addr(host);
	//in case of reverse lookup, the length is 13 characters more because of .in-addr.arpa
	if (ip != INADDR_NONE)
		size += 13;

	char* buf = new char[size];
	DNSHeader* dnsHeader = (DNSHeader*)buf;
	QueryHeader* queryHeader = (QueryHeader*)(buf + size - sizeof(QueryHeader));

	//construct header
	dnsHeader->id = htons(currentId);
	dnsHeader->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	dnsHeader->nQuestions = htons(1);
	dnsHeader->nAnswers = 0;
	dnsHeader->nAuthority = 0;
	dnsHeader->nAdditional = 0;

	//print query
	if (ip == INADDR_NONE){
		makeDNSQuestion((char*)(dnsHeader + 1), host);
		queryHeader->qType = htons(DNS_A);
		printf("Query	: %s, type %d, TXID 0x%.4X\n", host, ntohs(queryHeader->qType), currentId);
	}
	else {
		char* reversedHost = new char[strlen(host) + 14];
		reverseIp(reversedHost, host, strlen(host));
		makeDNSQuestion((char*)(dnsHeader + 1), reversedHost);

		queryHeader->qType = htons(DNS_PTR);
		printf("Query	: %s, type %d, TXID 0x%.4X\n", reversedHost, ntohs(queryHeader->qType), currentId);
		delete[] reversedHost;
	}
	queryHeader->qClass = htons(DNS_INET);

	struct sockaddr_in dnsServer;
	memset(&dnsServer, 0, sizeof(dnsServer));
	dnsServer.sin_family = AF_INET;
	dnsServer.sin_addr.s_addr = inet_addr(dns); // server’s IP
	dnsServer.sin_port = htons(53);	// DNS port on server

	//print server
	printf("Server	: %s\n", dns);
	printf("**************************************\n");

	FD_SET fd;
	struct timeval timeout;
	int count = 0;
	int start, end;
	while (count < MAX_ATTEMPTS){
		printf("Attempt %d with %d bytes... ", count, size);

		start = clock();
		if (sendto(sock, buf, size, 0, (struct sockaddr*)&dnsServer, sizeof(dnsServer)) == SOCKET_ERROR){
			printf("socket error %d\n", WSAGetLastError());
			delete[] buf;
			return false;
		}
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		FD_ZERO(&fd);
		FD_SET(sock, &fd);

		int ret;
		if ((ret = select(0, &fd, 0, 0, &timeout)) > 0){
			int len = sizeof(dnsServer);

			struct sockaddr_in response;
			if ((bytes = recvfrom(sock, responseBuf, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &len)) == SOCKET_ERROR){
				printf("socket error %d\n", WSAGetLastError());
				delete[] buf;
				return false;
			}
			if (bytes < MAX_DNS_SIZE)
				responseBuf[bytes] = 0;

			//check for malicious server
			if (memcmp(&response.sin_addr, &dnsServer.sin_addr, sizeof(DWORD)) != 0 || response.sin_port != dnsServer.sin_port){
				printf("bogus reply\n");
				delete[] buf;
				return false;
			}
			end = clock();
			printf("response in %.0f ms with %d bytes\n", Utils::duration(start, end), bytes);

			closesocket(sock);
			break;
		}
		else if (ret == 0){
			printf("timeout in %d ms\n", (timeout.tv_sec + timeout.tv_usec) * 1000);
			count++;
		}
		else {
			printf("socket error %d\n", WSAGetLastError());
			delete[] buf;
			return false;
		}
	}
	delete[] buf;
	if (count == MAX_ATTEMPTS)
		return false;
	return true;
}

//parse response
void DNSService::parse()
{
	if (bytes < 12){
		printf("  ++ invalid reply: smaller than fixed header\n");
		return;
	}

	DNSHeader* dnsHeader = (DNSHeader*)responseBuf;
	USHORT id = ntohs(dnsHeader->id);
	USHORT flags = ntohs(dnsHeader->flags);
	USHORT nQuestions = ntohs(dnsHeader->nQuestions);
	USHORT nAnswers = ntohs(dnsHeader->nAnswers);
	USHORT nAuthority = ntohs(dnsHeader->nAuthority);
	USHORT nAdditional = ntohs(dnsHeader->nAdditional);

	//print header
	printf("  TXID 0x%.4X, flags, 0x%.4X, questions %d, answers %d, authority %d, additional %d\n",
		id, flags, nQuestions, nAnswers, nAuthority, nAdditional);

	//invalid reply: mismatch TXID
	if (id != currentId){
		printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n", currentId, id);
		return;
	}

	//get reply code
	USHORT replyCode = (~(~0 << 4)) & flags;
	if (replyCode != DNS_OK){
		printf("  failed with Rcode = %d\n", replyCode);
		return;
	}
	printf("  succeeded with Rcode = %d\n", replyCode);

	ResourceRecord* resourceRecord = NULL;
	unsigned char* content = (unsigned char*)(dnsHeader + 1);

	//question section
	if (nQuestions > 0){
		printf("  ------------ [questions] ----------\n");
		if (!readQuestion(content, resourceRecord, nQuestions))
			return;
	}

	//answer section
	if (nAnswers > 0){
		printf("  ------------ [answers] ------------\n");
		if (!readAnswer(content, resourceRecord, nAnswers))
			return;
	}

	//authority section
	if (nAuthority > 0){
		printf("  ------------ [authority] ----------\n");
		if (!readAnswer(content, resourceRecord, nAuthority))
			return;
	}

	//additional section
	if (nAdditional > 0){
		printf("  ------------ [additional] ---------\n");
		if (!readAnswer(content, resourceRecord, nAdditional))
			return;
	}
}