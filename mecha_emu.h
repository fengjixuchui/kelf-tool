/*
	kelf-tool (adapted from ps3mca-tool) by zecoxao
 */

#ifndef __MECHAEMU_H__
#define __MECHAEMU_H__

#include <memory.h>
#include <stdlib.h>
#include <inttypes.h>

void meResetCryptoContext(void);
void meCardCalcUniqueKey(uint8_t *CardIV, uint8_t *CardMaterial);
void meCardGenerateChallenge(uint8_t *CardIV, uint8_t *CardNonce,
                             uint8_t *MechaNonce,
                             uint8_t *MechaChallenge1, uint8_t *MechaChallenge2, uint8_t *MechaChallenge3);
int meCardVerifyResponse(uint8_t *CardResponse1, uint8_t *CardResponse2, uint8_t *CardResponse3);
int meGetContentKeyOffset(uint8_t *KelfHeader);
void meDecryptDiskContentKey(uint8_t *KelfHeader);
void meEncryptCardContentKey(uint8_t *ContentKey);

#endif

