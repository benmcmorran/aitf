#include <tins/tins.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

using namespace Tins;

static struct timeval local_key_update;

static uint64_t local_key_1 = 0;
static uint64_t local_key_2 = 0;

static bool is_expired(struct timeval *last_update, struct timeval *now, int seconds) {
	long long change = (now->tv_sec - last_update->tv_sec) * 1000000 + now->tv_usec - last_update->tv_usec;
	return change > seconds * 1000000;
}

uint64_t generate_key() {
	// This does not use cryptographically secure random number generate to speed up testing
	// Real implementations would have a hardware source of entropy so a CSPRNG would be feasible
	uint64_t result = 0;
	RAND_bytes((unsigned char*)&result, 8);
	printf("generated %Ld\n", result);
	return result;
}

uint64_t hash_for_destination(IP::address_type address, int steps) {
	struct timeval now;
	gettimeofday(&now, NULL);

	if (is_expired(&local_key_update, &now, 10) || local_key_1 == 0 || local_key_2 == 0) {
		local_key_update = now;
		local_key_1 = generate_key();
		local_key_2 = generate_key();
	} else if (is_expired(&local_key_update, &now, 5)) {
		local_key_update = now;
		local_key_1 = local_key_2;
		local_key_2 = generate_key();
	}

	uint64_t local_key = steps == 0 ? local_key_1 : local_key_2;

	uint32_t message = (uint32_t)address;

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int length = EVP_MAX_MD_SIZE;
	HMAC(EVP_sha256(), (unsigned char*)&local_key, 8, (unsigned char*)&message, 4, digest, &length);

	return *(uint64_t*)digest;
}

/*
int main() {
	printf("Calling generate key three times\n");
	printf("%Ld, %Ld, %Ld\n\n", generate_key(), generate_key(), generate_key());

	printf("Calling hash for destination every second for 20 seconds on 192.168.10.10\n");
	for (int i = 0; i < 20; i++) {
		printf("Now: %Ld, next %Ld\n", hash_for_destination(IP::address_type("192.168.10.10"), 0), hash_for_destination(IP::address_type("192.168.10.10"), 1));
		usleep(1000000);
	}

	printf("Waiting 11 seconds before getting hash again\n");
	usleep(11000000);
	printf("Now: %Ld, next %Ld\n", hash_for_destination(IP::address_type("192.168.10.10"), 0), hash_for_destination(IP::address_type("192.168.10.10"), 1));
}
*/