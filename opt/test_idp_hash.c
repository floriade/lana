#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "../src/xt_idp.h"
#include "../src/xt_hash.h"
#define MAX_INS  (HASHTSIZ * 2)
int main(void)
{
	idp_t i;
	int coll = 0;
	int hist[HASHTSIZ];
	memset(hist, 0, sizeof(hist));
	for (i = 0; i < MAX_INS; ++i)
		hist[hash_idp2(i)]++;
	for (i = 0; i < HASHTSIZ; ++i) {
		if (hist[i] > 1)
			coll += (hist[i] - 1);
		printf("slot%d: %d\n", i, hist[i]);
	}
	printf("summary: %d collisions!\n", coll);
	return 0;
}
