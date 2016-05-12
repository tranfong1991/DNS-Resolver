/*
Name: Phong Tran
Class: CSCE 463-500
Acknowledgement: homework 2 handout
*/

#include"DNSService.h"

using namespace std;

int main(int argc, char* argv[])
{
	try{
		//check arguments
		if (argc != 3){
			printf("failed with too many or too few arguments\n");
			return 0;
		}

		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
			printf("WSAStartup error %d\n", WSAGetLastError());
			WSACleanup();
			return 0;
		}

		DNSService dns;
		if (!dns.setupSocket())
			return 0;
		if (!dns.query(argv[1], argv[2]))
			return 0;
		dns.parse();

		printf("\n\n");
		WSACleanup();
		return 0;
	}
	catch (...){
		printf("Unknown Exception!\n");
		WSACleanup();
	}
}