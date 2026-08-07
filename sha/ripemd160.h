#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

void ripemd160_hash(const uint8_t *msg, size_t msg_len, uint8_t out[20]);

#endif