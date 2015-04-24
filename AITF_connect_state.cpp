
AITF_connect::AITF_connect():
	current(1),nonce1(0),nonce2(0){}

int AITF_connect::currentRoute(){
	return current;
}

uint64_t AITF_connect::nonce1(){
	return nonce1;
}

uint64_t AITF_connect::nonce2(){
	return nonce2;
}

void AITF_connect::inc_currentRoute(){
	current++;
}

void AITF_connect::set_currentRoute(int x){
	current = x;
}

void AITF_connect::set_nonce1(uint64_t n1){
	nonce1 = n1;
}

void AITF_connect::set_nonce2(uint64_t n2){
	nonce2 = n2;
}