#ifndef AIRGAP_QR_H
#define AIRGAP_QR_H

#include <stdint.h>

/*
 * Minimal QR Code Model 2 encoder for AirgapBIP39.
 *
 * Scope is deliberately narrow:
 *   - QR Version 3 (29 x 29 modules)
 *   - Error correction level L
 *   - Alphanumeric mode
 *   - Up to 77 QR-alphanumeric characters
 *
 * A mainnet Taproot Bech32m address is 62 characters. AirgapBIP39 converts
 * the address to uppercase before encoding; Bech32/Bech32m permits an address
 * to be entirely lowercase or entirely uppercase (mixed case is invalid).
 *
 * No heap allocation is used.
 */

#define AIRGAP_QR_SIZE 29
#define AIRGAP_QR_MAX_ALNUM 77
#define AIRGAP_QR_QUIET_ZONE 4

typedef struct {
    uint8_t module[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE];
} airgap_qr;

/* Returns 1 on success, 0 if text cannot be encoded by this fixed profile. */
int airgap_qr_encode_alphanumeric(const char *text, airgap_qr *out);
int airgap_qr_print_terminal(const airgap_qr *qr);

#endif
