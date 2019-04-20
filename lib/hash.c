#include "hash.h"

unsigned int crc32 (unsigned char *str)
{
    unsigned int crc, c;
    while (c=*str++)
    {
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ c) & 255];
    }
    return crc;
}

unsigned int crc16(unsigned char *data_p, unsigned short length)
{
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;
    if (length == 0)return (~crc);
    do
    {
        for(i=0, data=(unsigned int)0xff & *data_p++;
            i < 8; i++, data >>= 1)
        {
            if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ POLY;
            else  crc >>= 1;
        }
    } while (--length);
    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);
    return (crc);
}

unsigned long djb2(unsigned char *str){
    unsigned long hash = 5381;
    int c;
    while(c=*str++){
        hash = ((hash << 5)+hash)+c;
    }
    return hash;
}

unsigned int jenkins(unsigned char *str){
    unsigned int hash = 0;
    while(*str){
        hash += *str;
        hash += (hash << 10);
        hash ^= (hash >> 6);
        str++;
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

unsigned long sdbm(unsigned char *str){
    unsigned long hash = 0;
    int c;
    while (c = *str++)
        hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

unsigned long loselose(unsigned char *str){
    unsigned int hash = 0;
    int c;
    while (c = *str++)
	    hash += c;
	return hash;
}

uint32_t _rotl(const uint32_t val, int shift){
    if ((shift &= sizeof(val)*8 - 1) == 0)
        return val;
    return (val << shift) | (val >> (sizeof(val)*8 - shift));
}

uint32_t _rotr(const uint32_t val, int shift){
    if((shift &= sizeof(val)*8 - 1) == 0)
        return val;
    return (val >> shift) | (val << (sizeof(val)*8 - shift));
}

unsigned long xxhash32(unsigned char *str, unsigned int seed){
    uint32_t acc1,acc2,acc3,acc4;
    uint32_t acc, c;

    acc = *str++;

    acc1 = seed + PRIME32_1 + PRIME32_2;
    acc2 = seed + PRIME32_2;
    acc3 = seed;
    acc4 = seed - PRIME32_1;

    acc1 = acc1 + (acc * PRIME32_2);
    acc1 = _rotl(acc1, 13);
    acc1 = acc1 * PRIME32_1;

    acc = _rotl(acc1, 1) + _rotl(acc2, 7) + 
        _rotl(acc3, 12) + _rotl(acc4, 18);

    acc += 16;

    while(c=*str++){
        c = acc + c * PRIME32_5;
        acc = _rotl(acc, 11);
        c = acc * PRIME32_1;

        c = c ^ (c >> 15);
        c = c * PRIME32_2;
        c = c ^ (c >> 13);
        c = c * PRIME32_3;
        c = c ^ (c >> 16);

        acc = c;
    }

    return acc;
}