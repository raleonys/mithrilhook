// SPDX-License-Identifier: GPL-3.0-only
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_M_X64) || defined(__x86_64__)
#include "hde/hde64.h"
#define DECODE MthInternal_hde64_disasm
#define DECODED hde64s
#else
#include "hde/hde32.h"
#define DECODE MthInternal_hde32_disasm
#define DECODED hde32s
#endif
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL: decoder %s\n",#x);return 1;} } while(0)
int main(void) {
    static const uint8_t call[]={0xe8,0x78,0x56,0x34,0x12};
    static const uint8_t push[]={0x68,0x78,0x56,0x34,0x12};
    static const uint8_t mov16[]={0x66,0xb8,0x34,0x12};
    uint8_t buffer[64];
    for(unsigned offset=0;offset<16;++offset) {
        DECODED decoded;
        memset(buffer,0x90,sizeof(buffer));memcpy(buffer+offset,call,sizeof(call));
        CHECK(DECODE(buffer+offset,&decoded)==5 && !(decoded.flags&F_ERROR));
        CHECK(decoded.flags&F_RELATIVE);CHECK(decoded.imm.imm32==0x12345678);
        memcpy(buffer+offset,push,sizeof(push));
        CHECK(DECODE(buffer+offset,&decoded)==5 && !(decoded.flags&F_ERROR));
        CHECK(decoded.imm.imm32==0x12345678);
        memcpy(buffer+offset,mov16,sizeof(mov16));
        CHECK(DECODE(buffer+offset,&decoded)==4 && !(decoded.flags&F_ERROR));
        CHECK(decoded.imm.imm16==0x1234);
    }
    printf("PASS: %u actual decoder checks across all byte alignments\n",checks);return 0;
}
