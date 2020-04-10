#include "miner.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/gost_streebog.h"
#include "lyra2/Lyra2.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_echo.h"


void arctichash_hash(void *output, const void *input)
{
    sph_whirlpool_context    ctx_whirlpool;
    sph_bmw512_context       ctx_bmw;
    sph_echo512_context      ctx_echo;
    sph_groestl512_context   ctx_groestl;
    sph_gost512_context      ctx_gost;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_simd512_context      ctx_simd;
    
    size_t nOutLen = 64;
    uint8_t hash[26 * 64] = {0};
    
    // Round 1
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, input, 80);
    sph_whirlpool_close(&ctx_whirlpool, hash);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash, nOutLen);
    sph_bmw512_close(&ctx_bmw, hash + 1*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 1*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 2);
    
    LYRA2(hash + 3*nOutLen, nOutLen, hash + 2*nOutLen, nOutLen, hash + 2*nOutLen, nOutLen, 1, 8, 8);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 3*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 4*nOutLen);
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 4*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 5*nOutLen);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash + 5*nOutLen, nOutLen);
    sph_jh512_close(&ctx_jh, hash + 6*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 6*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 7*nOutLen);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hash + 7*nOutLen, nOutLen);
    sph_blake512_close(&ctx_blake, hash + 8*nOutLen);
    
    // Round 2
    
    LYRA2(hash + 9*nOutLen, nOutLen, hash + 8*nOutLen, nOutLen, hash + 8*nOutLen, nOutLen, 1, 8, 8);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hash + 9*nOutLen, nOutLen);
    sph_whirlpool_close(&ctx_whirlpool, hash + 10*nOutLen);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash + 10*nOutLen, nOutLen);
    sph_cubehash512_close(&ctx_cubehash, hash + 11*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 11*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 12*nOutLen);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 12*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 13*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 13*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 14*nOutLen);
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 14*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 15*nOutLen);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 15*nOutLen, nOutLen);
    sph_simd512_close(&ctx_simd, hash + 16*nOutLen);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash + 16*nOutLen, nOutLen);
    sph_bmw512_close(&ctx_bmw, hash + 17*nOutLen);
    
    // Round 3
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 17*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 18*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 18*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 19*nOutLen);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash + 19*nOutLen, nOutLen);
    sph_cubehash512_close(&ctx_cubehash, hash + 20*nOutLen);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 20*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 21*nOutLen);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash + 21*nOutLen, nOutLen);
    sph_jh512_close(&ctx_jh, hash + 22*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 22*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 23*nOutLen);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 23*nOutLen, nOutLen);
    sph_simd512_close(&ctx_simd, hash + 24*nOutLen);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hash + 24*nOutLen, nOutLen);
    sph_blake512_close(&ctx_blake, hash + 25*nOutLen);
    
    LYRA2(output, 32, hash + 25*nOutLen, nOutLen, hash + 25*nOutLen, nOutLen, 1, 8, 8);
	
}

int scanhash_arctichash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], nonce);
		arctichash_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
