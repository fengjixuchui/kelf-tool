/*
	kelf-tool (adapted from ps3mca-tool) by zecoxao
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <inttypes.h>

#include "mecha_emu.h"

/*
 * meDecryptDiskContentKey: Decrypt the encrypted ContentKey for disk/rom
 * from a given Kelf header
 */
//void meDecryptDiskContentKey(uint8_t *KelfHeader)

int main(int argc, char** argv){
	if(argc < 3){
		printf("Usage: %s [kelf] [kelf.dec] \n", argv[0]);
		return 1;
	}
	
	FILE * fin = fopen(argv[1],"rb");
	fseek(fin, 0, SEEK_END);
	unsigned long fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);  /* same as rewind(f); */

	unsigned char *buf = malloc(fsize + 1);
	fread(buf, 1, fsize, fin);
	fclose(fin);
	
	meDecryptDiskContentKey(buf);

	FILE * fout = fopen(argv[2],"wb");
	fwrite(buf,1,fsize,fout);
	fclose(fout);
	
	free(buf);
	
	return 0;
}