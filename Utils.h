/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include <string>

using namespace std;

class Utils{
public:
	static int myStrCopy(char* src, char* des, int len)
	{
		for (int i = 0; i < len; i++){
			//missing characters
			if (src[i] == 0 && i < len - 1)
				return -1;
			des[i] = src[i];
		}
		return len;
	}

	//return duration in ms
	static	double duration(int start, int end)
	{
		return (end - start) * 1000 / (double)CLOCKS_PER_SEC;
	}

	//insert and check if the num is unique
	static bool isUnique(unordered_set<int>& mySet, int num)
	{
		int prevSize = mySet.size();
		mySet.insert(num);

		if (prevSize < mySet.size())
			return true;
		return false;
	}
};