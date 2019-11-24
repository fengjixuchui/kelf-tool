/*
	kelf-tool (adapted from ps3mca-tool) by zecoxao
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <memory.h>
#include <stdlib.h>
#include <inttypes.h>

void memrcpy(void *dst, void *src, size_t len);
void memxor(const void *a, const void *b, void *Result, size_t Length);
void append_le_uint16(uint8_t *buf, uint16_t val);
void append_le_uint32(uint8_t *buf, uint32_t val);
void append_le_uint64(uint8_t *buf, uint64_t val);
uint16_t read_le_uint16(const uint8_t *buf);
uint32_t read_le_uint32(const uint8_t *buf);
uint64_t read_le_uint64(const uint8_t *buf);

#endif

