/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include <winsock.h>
#include <ctime>
#include <stack>
#include <unordered_set>
#include "Utils.h"

//only useful query class
#define DNS_INET 1	

//dns query types
#define DNS_A 1			//name -> IP
#define DNS_NS 2		//name server
#define DNS_CNAME 5		//canonical name
#define DNS_PTR 12		//IP -> name
#define DNS_HINFO 13	//host info/SOA
#define DNS_MX 15		//mail exchange
#define DNS_AXFR 252	//request for zone transfer
#define DNS_ANY 255		//all records

//flags
#define DNS_QUERY (0<<15)
#define DNS_RESPONSE (1<<15)
#define DNS_STDQUERY (0<<11)
#define DNS_AA (1<10)
#define DNS_TC (1<<9)
#define DNS_RD (1<<8)
#define DNS_RA (1<<7)

//result codes
#define DNS_OK 0			//rcode = reply codes
#define DNS_FORMAT 1		//format error (unable to interpret)
#define DNS_SERVERFAIL 2	//can't find authority nameserver
#define DNS_ERROR 3			//no DNS entry
#define DNS_NOTIMPL 4		//not implemented
#define DNS_REFUSED 5		//server refused the query

#define MAX_ATTEMPTS 3
#define MAX_DNS_SIZE 512

#pragma pack(push, 1)
struct ResourceRecord{
	USHORT rType;
	USHORT rClass;
	UINT ttl;
	USHORT rLength;
};

struct QueryHeader{
	USHORT qType;
	USHORT qClass;
};

struct DNSHeader{
	USHORT id;
	USHORT flags;
	USHORT nQuestions;
	USHORT nAnswers;
	USHORT nAuthority;
	USHORT nAdditional;
};
#pragma pack(pop)

class DNSService{
	SOCKET sock;
	USHORT currentId = 1;
	int bytes;
	char responseBuf[MAX_DNS_SIZE];

	string toIP(unsigned char* ptr, int len);
	string toRRType(USHORT t);
	void makeDNSQuestion(char* buf, char* host);
	void reverseIp(char* buf, char* ip, int len);
	bool readQuestion(unsigned char*& content, ResourceRecord* resourceRecord, int n);
	bool readAnswer(unsigned char*& content, ResourceRecord* resourceRecord, int n);
	unsigned char* resolveName(unsigned char* buf, unsigned char* name, char* response);
public:
	DNSService();
	~DNSService();

	bool setupSocket();
	bool query(char* host, char* dns);
	void parse();
};