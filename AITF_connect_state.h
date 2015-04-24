#pragma once
#include <tins/tins.h>
#include <cassert>

using namespace Tins;
using namespace std;

class AITF_connect_state{
public:
	AITF_connect_state();

	uint64_t nonce1();
	uint64_t nonce2();
	int currentRoute();

	void set_currentRoute(int x);
	void set_nonce1(uint64_t n1);
	void set_nonce2(uint64_t n2);

private:
	int _current;
	uint64_t _nonce1;
	uint64_t _nonce2;

};