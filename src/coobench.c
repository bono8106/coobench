/*
 ============================================================================
 Name        : coobench.c
 Author      : Nikolay Botev
 Version     :
 Copyright   : Copyright (c) 2011 Nikolay Botev; SHA1 code derived from
               libpurple
 Description : SHA1 code derived from pidgin 2.10.0 source -
               libpurple/ciphers/sha1.c
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include <linux/time.h>

#include <glib.h>
#include <string.h>

#define SHA1_HMAC_BLOCK_SIZE    64
#define SHA1_ROTL(X,n) ((((X) << (n)) | ((X) >> (32-(n)))) & 0xFFFFFFFF)

struct SHA1Context {
	guint32 H[5];
	guint32 W[80];

	gint lenW;

	guint32 sizeHi;
	guint32 sizeLo;
};

static void
sha1_hash_block(struct SHA1Context *sha1_ctx) {
	gint i;
	guint32 A, B, C, D, E, T;

	for(i = 16; i < 80; i++) {
		sha1_ctx->W[i] = SHA1_ROTL(sha1_ctx->W[i -  3] ^
				sha1_ctx->W[i -  8] ^
				sha1_ctx->W[i - 14] ^
				sha1_ctx->W[i - 16], 1);
	}

	A = sha1_ctx->H[0];
	B = sha1_ctx->H[1];
	C = sha1_ctx->H[2];
	D = sha1_ctx->H[3];
	E = sha1_ctx->H[4];

	for(i = 0; i < 20; i++) {
		T = (SHA1_ROTL(A, 5) + (((C ^ D) & B) ^ D) + E + sha1_ctx->W[i] + 0x5A827999) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 20; i < 40; i++) {
		T = (SHA1_ROTL(A, 5) + (B ^ C ^ D) + E + sha1_ctx->W[i] + 0x6ED9EBA1) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 40; i < 60; i++) {
		T = (SHA1_ROTL(A, 5) + ((B & C) | (D & (B | C))) + E + sha1_ctx->W[i] + 0x8F1BBCDC) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 60; i < 80; i++) {
		T = (SHA1_ROTL(A, 5) + (B ^ C ^ D) + E + sha1_ctx->W[i] + 0xCA62C1D6) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	sha1_ctx->H[0] += A;
	sha1_ctx->H[1] += B;
	sha1_ctx->H[2] += C;
	sha1_ctx->H[3] += D;
	sha1_ctx->H[4] += E;
}

static void
sha1_init(struct SHA1Context **sha1_ctx) {
	*sha1_ctx = g_new0(struct SHA1Context, 1);
}

static void
sha1_reset(struct SHA1Context *sha1_ctx, void *extra) {
	gint i;

	g_return_if_fail(sha1_ctx);

	sha1_ctx->lenW = 0;
	sha1_ctx->sizeHi = 0;
	sha1_ctx->sizeLo = 0;

	sha1_ctx->H[0] = 0x67452301;
	sha1_ctx->H[1] = 0xEFCDAB89;
	sha1_ctx->H[2] = 0x98BADCFE;
	sha1_ctx->H[3] = 0x10325476;
	sha1_ctx->H[4] = 0xC3D2E1F0;

	for(i = 0; i < 80; i++)
		sha1_ctx->W[i] = 0;
}

static void
sha1_uninit(struct SHA1Context *sha1_ctx) {
	memset(sha1_ctx, 0, sizeof(struct SHA1Context));

	g_free(sha1_ctx);
	sha1_ctx = NULL;
}

static void
sha1_append(struct SHA1Context *sha1_ctx, const guchar *data, size_t len) {
	gint i;

	g_return_if_fail(sha1_ctx);

	for(i = 0; i < len; i++) {
		sha1_ctx->W[sha1_ctx->lenW / 4] <<= 8;
		sha1_ctx->W[sha1_ctx->lenW / 4] |= data[i];

		if((++sha1_ctx->lenW) % 64 == 0) {
			sha1_hash_block(sha1_ctx);
			sha1_ctx->lenW = 0;
		}

		sha1_ctx->sizeLo += 8;
		sha1_ctx->sizeHi += (sha1_ctx->sizeLo < 8);
	}
}

static gboolean
sha1_digest(struct SHA1Context *sha1_ctx, size_t in_len, guchar digest[20],
            size_t *out_len)
{
	guchar pad0x80 = 0x80, pad0x00 = 0x00;
	guchar padlen[8];
	gint i;

	g_return_val_if_fail(in_len >= 20, FALSE);

	g_return_val_if_fail(sha1_ctx, FALSE);

	padlen[0] = (guchar)((sha1_ctx->sizeHi >> 24) & 255);
	padlen[1] = (guchar)((sha1_ctx->sizeHi >> 16) & 255);
	padlen[2] = (guchar)((sha1_ctx->sizeHi >> 8) & 255);
	padlen[3] = (guchar)((sha1_ctx->sizeHi >> 0) & 255);
	padlen[4] = (guchar)((sha1_ctx->sizeLo >> 24) & 255);
	padlen[5] = (guchar)((sha1_ctx->sizeLo >> 16) & 255);
	padlen[6] = (guchar)((sha1_ctx->sizeLo >> 8) & 255);
	padlen[7] = (guchar)((sha1_ctx->sizeLo >> 0) & 255);

	/* pad with a 1, then zeroes, then length */
	sha1_append(sha1_ctx, &pad0x80, 1);
	while(sha1_ctx->lenW != 56)
		sha1_append(sha1_ctx, &pad0x00, 1);
	sha1_append(sha1_ctx, padlen, 8);

	for(i = 0; i < 20; i++) {
		digest[i] = (guchar)(sha1_ctx->H[i / 4] >> 24);
		sha1_ctx->H[i / 4] <<= 8;
	}

	sha1_reset(sha1_ctx, NULL);

	if(out_len)
		*out_len = 20;

	return TRUE;
}

inline static long nanoTime()
{
	struct timespec res;
	clock_gettime(CLOCK_REALTIME, &res);
	return ((long) res.tv_sec) * 1000000000L + res.tv_nsec;
}

void doItDigestRealloc(int n) {
	gchar *fox = "The quick brown fox jumped over the lazy dog.\n";
	long int startTime = nanoTime();

	int result = 0;
	for (int i = 1; i <= n; i++) {
		guchar *digest;
		size_t digest_length;

		struct SHA1Context* sha1;
		sha1_init(&sha1);
		sha1_reset(sha1, NULL);
		sha1_append(sha1, (guchar*) fox, strlen(fox));
		digest = malloc(sizeof(guchar) * 20);
		sha1_digest(sha1, 20, digest, &digest_length);
		result += digest_length;
		free(digest);
		sha1_uninit(sha1);
	}

	long int endTime = nanoTime();
	long int time = endTime - startTime;
	double avgTime = time / n / 1000.0;
	printf("  executions: %07d; avg time = %.2f micros\n", n, avgTime);
}

void doIt(int n) {
	gchar *fox = "The quick brown fox jumped over the lazy dog.\n";
	long int startTime = nanoTime();

	int result = 0;
	for (int i = 1; i <= n; i++) {
		guchar digest[20];
		size_t digest_length;

		struct SHA1Context* sha1;
		sha1_init(&sha1);
		sha1_reset(sha1, NULL);
		sha1_append(sha1, (guchar*) fox, strlen(fox));
		sha1_digest(sha1, 20, digest, &digest_length);
		result += digest_length;
		sha1_uninit(sha1);
	}

	long int endTime = nanoTime();
	long int time = endTime - startTime;
	double avgTime = time / n / 1000.0;
	printf("  executions: %07d; avg time = %.2f micros\n", n, avgTime);
}

void doItNoRealloc(int n) {
	gchar *fox = "The quick brown fox jumped over the lazy dog.\n";
	long int startTime = nanoTime();

	int result = 0;
	struct SHA1Context* sha1;
	sha1_init(&sha1);
	sha1_reset(sha1, NULL);
	for (int i = 1; i <= n; i++) {
		guchar digest[20];
		size_t digest_length;

		sha1_append(sha1, (guchar*) fox, strlen(fox));
		sha1_digest(sha1, 20, digest, &digest_length);
		result += digest_length;
	}
	sha1_uninit(sha1);

	long int endTime = nanoTime();
	long int time = endTime - startTime;
	double avgTime = time / n / 1000.0;
	printf("  executions: %07d; avg time = %.2f micros\n", n, avgTime);
}

void testSHA1()
{
    gchar *fox = "The quick brown fox jumped over the lazy dog.\n";
    struct SHA1Context *sha1;
    guchar digest[20];

    long int start = nanoTime();

    sha1_init(&sha1);
    sha1_reset(sha1, NULL);
    sha1_append(sha1, (guchar*)fox, strlen(fox));
    sha1_digest(sha1, 20, digest, NULL);
    sha1_uninit(sha1);

    long int end = nanoTime();
    long int time = end - start;
    printf("Time to run: %ld ns\n", time);

    for(int i = 0;i < 20;i++){
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main(void) {

	printf("Testing with SHA1 and digest realloc on each run:\n");
    doItDigestRealloc(1000);
    doItDigestRealloc(10000);
    doItDigestRealloc(100000);
    doItDigestRealloc(1000000);
    doItDigestRealloc(3000000);

	printf("Testing with SHA1 realloc on each run:\n");
    doIt(1000);
    doIt(10000);
    doIt(100000);
    doIt(1000000);
    doIt(3000000);

	printf("Testing with no realloc on each run:\n");
    doItNoRealloc(1000);
    doItNoRealloc(10000);
    doItNoRealloc(100000);
    doItNoRealloc(1000000);
    doItNoRealloc(3000000);

	return EXIT_SUCCESS;
}
