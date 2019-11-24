/*
	kelf-tool (adapted from ps3mca-tool) by zecoxao
 */
 
#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <memory.h>
#include <stdlib.h>
#include <inttypes.h>

int cipherCbcEncrypt(uint8_t *Result, const uint8_t *Data, size_t Length, 
                     const uint8_t *Keys, int KeyCount, const uint8_t IV[8]);
int cipherCbcDecrypt(uint8_t *Result, const uint8_t *Data, size_t Length,
                     const uint8_t *Keys, int KeyCount,	const uint8_t IV[8]);

#endif
