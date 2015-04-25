#include "AITF_connect_state.h"

AITF_connect_state::AITF_connect_state():
	_current(1),_nonce1(0),_nonce2(0){}

AITF_connect_state::AITF_connect_state(int c, uint64_t n1, uint64_t n2):
	_current(c), _nonce1(n1), _nonce2(n2){}

AITF_connect_state::AITF_connect_state(AITF_connect_state (* const)() )
{

}

int AITF_connect_state::currentRoute(){
	return _current;
}

uint64_t AITF_connect_state::nonce1(){
	return _nonce1;
}

uint64_t AITF_connect_state::nonce2(){
	return _nonce2;
}

void AITF_connect_state::inc_currentRoute(){
	_current++;
}

void AITF_connect_state::set_currentRoute(int x){
	_current = x;
}

void AITF_connect_state::set_nonce1(uint64_t n1){
	_nonce1 = n1;
}

void AITF_connect_state::set_nonce2(uint64_t n2){
	_nonce2 = n2;
}
