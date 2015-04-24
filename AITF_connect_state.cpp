#include <"AITF_connect_state.h">

AITF_connect::AITF_connect():
	_current(1),_nonce1(0),_nonce2(0){}

int AITF_connect::currentRoute(){
	return _current;
}

uint64_t AITF_connect::nonce1(){
	return _nonce1;
}

uint64_t AITF_connect::nonce2(){
	return _nonce2;
}

void AITF_connect::inc_currentRoute(){
	_current++;
}

void AITF_connect::set_currentRoute(int x){
	_current = x;
}

void AITF_connect::set_nonce1(uint64_t n1){
	_nonce1 = n1;
}

void AITF_connect::set_nonce2(uint64_t n2){
	_nonce2 = n2;
}