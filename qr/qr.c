#include "qr.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#endif

/* QR Version 3-L: 70 total codewords = 55 data + 15 ECC, one RS block. */
#define QR_DATA_CODEWORDS 55
#define QR_ECC_CODEWORDS  15
#define QR_TOTAL_CODEWORDS 70
#define QR_DATA_BITS (QR_DATA_CODEWORDS * 8)

static const char QR_ALNUM[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

static int alnum_value(char c) {
    const char *p = strchr(QR_ALNUM, c);
    return p == NULL ? -1 : (int)(p - QR_ALNUM);
}

static int append_bits(uint8_t data[QR_DATA_CODEWORDS], int *bitlen,
                       unsigned value, int count) {
    if (count < 0 || count > 16 || *bitlen < 0 || *bitlen + count > QR_DATA_BITS)
        return 0;
    for (int i = count - 1; i >= 0; i--) {
        int pos = (*bitlen)++;
        if (((value >> i) & 1U) != 0U)
            data[pos >> 3] |= (uint8_t)(1U << (7 - (pos & 7)));
    }
    return 1;
}

static int make_data_codewords(const char *text, uint8_t out[QR_DATA_CODEWORDS]) {
    size_t len = strlen(text);
    int bitlen = 0;
    if (len > AIRGAP_QR_MAX_ALNUM) return 0;
    memset(out, 0, QR_DATA_CODEWORDS);

    /* Mode 0010 = alphanumeric. Version 1..9 uses a 9-bit character count. */
    if (!append_bits(out, &bitlen, 0x2U, 4)) return 0;
    if (!append_bits(out, &bitlen, (unsigned)len, 9)) return 0;

    size_t i = 0;
    while (i + 1U < len) {
        int a = alnum_value(text[i]);
        int b = alnum_value(text[i + 1U]);
        if (a < 0 || b < 0) return 0;
        if (!append_bits(out, &bitlen, (unsigned)(45 * a + b), 11)) return 0;
        i += 2U;
    }
    if (i < len) {
        int a = alnum_value(text[i]);
        if (a < 0 || !append_bits(out, &bitlen, (unsigned)a, 6)) return 0;
    }

    /* Terminator, byte alignment, then standard 0xEC/0x11 pad bytes. */
    int terminator = QR_DATA_BITS - bitlen;
    if (terminator > 4) terminator = 4;
    if (!append_bits(out, &bitlen, 0U, terminator)) return 0;
    while ((bitlen & 7) != 0) {
        if (!append_bits(out, &bitlen, 0U, 1)) return 0;
    }

    int bytepos = bitlen >> 3;
    uint8_t pad = 0xECU;
    while (bytepos < QR_DATA_CODEWORDS) {
        out[bytepos++] = pad;
        pad = (pad == 0xECU) ? 0x11U : 0xECU;
    }
    return 1;
}

/* GF(256), primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D). */
static uint8_t gf_mul(uint8_t x, uint8_t y) {
    unsigned z = 0U;
    unsigned a = x;
    unsigned b = y;
    while (b != 0U) {
        if ((b & 1U) != 0U) z ^= a;
        b >>= 1;
        a <<= 1;
        if ((a & 0x100U) != 0U) a ^= 0x11DU;
    }
    return (uint8_t)z;
}

static void rs_generator(uint8_t gen[QR_ECC_CODEWORDS]) {
    memset(gen, 0, QR_ECC_CODEWORDS);
    gen[QR_ECC_CODEWORDS - 1] = 1U;
    uint8_t root = 1U;
    for (int i = 0; i < QR_ECC_CODEWORDS; i++) {
        for (int j = 0; j < QR_ECC_CODEWORDS; j++) {
            gen[j] = gf_mul(gen[j], root);
            if (j + 1 < QR_ECC_CODEWORDS) gen[j] ^= gen[j + 1];
        }
        root = gf_mul(root, 0x02U);
    }
}

static void rs_remainder(const uint8_t data[QR_DATA_CODEWORDS],
                         uint8_t ecc[QR_ECC_CODEWORDS]) {
    uint8_t gen[QR_ECC_CODEWORDS];
    rs_generator(gen);
    memset(ecc, 0, QR_ECC_CODEWORDS);
    for (int i = 0; i < QR_DATA_CODEWORDS; i++) {
        uint8_t factor = (uint8_t)(data[i] ^ ecc[0]);
        memmove(ecc, ecc + 1, QR_ECC_CODEWORDS - 1U);
        ecc[QR_ECC_CODEWORDS - 1] = 0U;
        for (int j = 0; j < QR_ECC_CODEWORDS; j++)
            ecc[j] ^= gf_mul(gen[j], factor);
    }
    memset(gen, 0, sizeof(gen));
}

static void set_function(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                         uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                         int x, int y, int dark) {
    if (x < 0 || y < 0 || x >= AIRGAP_QR_SIZE || y >= AIRGAP_QR_SIZE) return;
    modules[y][x] = (uint8_t)(dark != 0);
    function[y][x] = 1U;
}

static void draw_finder(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                        uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                        int cx, int cy) {
    for (int dy = -4; dy <= 4; dy++) {
        for (int dx = -4; dx <= 4; dx++) {
            int distx = dx < 0 ? -dx : dx;
            int disty = dy < 0 ? -dy : dy;
            int dist = distx > disty ? distx : disty;
            int dark = dist != 2 && dist != 4;
            set_function(modules, function, cx + dx, cy + dy, dark);
        }
    }
}

static void draw_alignment(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                           uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                           int cx, int cy) {
    for (int dy = -2; dy <= 2; dy++) {
        for (int dx = -2; dx <= 2; dx++) {
            int ax = dx < 0 ? -dx : dx;
            int ay = dy < 0 ? -dy : dy;
            int dist = ax > ay ? ax : ay;
            set_function(modules, function, cx + dx, cy + dy, dist != 1);
        }
    }
}

static unsigned format_bits_for_mask(int mask) {
    /* Error correction level L has format value 01. */
    unsigned data = (1U << 3) | (unsigned)mask;
    unsigned rem = data;
    for (int i = 0; i < 10; i++)
        rem = (rem << 1) ^ (((rem >> 9) & 1U) * 0x537U);
    return ((data << 10) | rem) ^ 0x5412U;
}

static void draw_format(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                        uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                        int mask) {
    unsigned bits = format_bits_for_mask(mask);
    for (int i = 0; i <= 5; i++)
        set_function(modules, function, 8, i, (int)((bits >> i) & 1U));
    set_function(modules, function, 8, 7, (int)((bits >> 6) & 1U));
    set_function(modules, function, 8, 8, (int)((bits >> 7) & 1U));
    set_function(modules, function, 7, 8, (int)((bits >> 8) & 1U));
    for (int i = 9; i < 15; i++)
        set_function(modules, function, 14 - i, 8, (int)((bits >> i) & 1U));

    for (int i = 0; i < 8; i++)
        set_function(modules, function, AIRGAP_QR_SIZE - 1 - i, 8,
                     (int)((bits >> i) & 1U));
    for (int i = 8; i < 15; i++)
        set_function(modules, function, 8, AIRGAP_QR_SIZE - 15 + i,
                     (int)((bits >> i) & 1U));

    /* Fixed dark module. */
    set_function(modules, function, 8, AIRGAP_QR_SIZE - 8, 1);
}

static void draw_function_patterns(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                                   uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                                   int mask) {
    memset(modules, 0, AIRGAP_QR_SIZE * AIRGAP_QR_SIZE);
    memset(function, 0, AIRGAP_QR_SIZE * AIRGAP_QR_SIZE);

    draw_finder(modules, function, 3, 3);
    draw_finder(modules, function, AIRGAP_QR_SIZE - 4, 3);
    draw_finder(modules, function, 3, AIRGAP_QR_SIZE - 4);

    for (int i = 8; i < AIRGAP_QR_SIZE - 8; i++) {
        set_function(modules, function, 6, i, (i & 1) == 0);
        set_function(modules, function, i, 6, (i & 1) == 0);
    }

    /* Version 3 alignment centers are 6 and 22; only (22,22) does not overlap. */
    draw_alignment(modules, function, 22, 22);
    draw_format(modules, function, mask);
}

static int mask_bit(int mask, int x, int y) {
    switch (mask) {
        case 0: return ((x + y) & 1) == 0;
        case 1: return (y & 1) == 0;
        case 2: return x % 3 == 0;
        case 3: return (x + y) % 3 == 0;
        case 4: return ((y / 2) + (x / 3)) % 2 == 0;
        case 5: return ((x * y) % 2 + (x * y) % 3) == 0;
        case 6: return (((x * y) % 2 + (x * y) % 3) & 1) == 0;
        case 7: return (((x + y) % 2 + (x * y) % 3) & 1) == 0;
        default: return 0;
    }
}

static void place_codewords(uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                            const uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE],
                            const uint8_t codewords[QR_TOTAL_CODEWORDS], int mask) {
    int bit = 0;
    int upward = 1;

    for (int right = AIRGAP_QR_SIZE - 1; right >= 1; right -= 2) {
        if (right == 6) right--;
        for (int vert = 0; vert < AIRGAP_QR_SIZE; vert++) {
            int y = upward ? AIRGAP_QR_SIZE - 1 - vert : vert;
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                if (function[y][x] != 0U) continue;
                int dark = 0;
                if (bit < QR_TOTAL_CODEWORDS * 8)
                    dark = (codewords[bit >> 3] >> (7 - (bit & 7))) & 1;
                if (mask_bit(mask, x, y)) dark ^= 1;
                modules[y][x] = (uint8_t)dark;
                bit++;
            }
        }
        upward = !upward;
    }
}

/* QR penalty scoring; used only to choose among the 8 legal masks. */
static long penalty_score(const uint8_t m[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE]) {
    long score = 0;

    for (int y = 0; y < AIRGAP_QR_SIZE; y++) {
        int run = 1;
        for (int x = 1; x < AIRGAP_QR_SIZE; x++) {
            if (m[y][x] == m[y][x - 1]) {
                run++;
                if (run == 5) score += 3;
                else if (run > 5) score++;
            } else run = 1;
        }
    }
    for (int x = 0; x < AIRGAP_QR_SIZE; x++) {
        int run = 1;
        for (int y = 1; y < AIRGAP_QR_SIZE; y++) {
            if (m[y][x] == m[y - 1][x]) {
                run++;
                if (run == 5) score += 3;
                else if (run > 5) score++;
            } else run = 1;
        }
    }

    for (int y = 0; y < AIRGAP_QR_SIZE - 1; y++)
        for (int x = 0; x < AIRGAP_QR_SIZE - 1; x++) {
            int s = m[y][x] + m[y][x + 1] + m[y + 1][x] + m[y + 1][x + 1];
            if (s == 0 || s == 4) score += 3;
        }

    /* Finder-like 1:1:3:1:1 patterns with four light modules before/after. */
    static const uint8_t pat1[11] = {1,0,1,1,1,0,1,0,0,0,0};
    static const uint8_t pat2[11] = {0,0,0,0,1,0,1,1,1,0,1};
    for (int y = 0; y < AIRGAP_QR_SIZE; y++) {
        for (int x = 0; x <= AIRGAP_QR_SIZE - 11; x++) {
            int a = 1, b = 1;
            for (int k = 0; k < 11; k++) {
                a &= m[y][x + k] == pat1[k];
                b &= m[y][x + k] == pat2[k];
            }
            if (a || b) score += 40;
        }
    }
    for (int x = 0; x < AIRGAP_QR_SIZE; x++) {
        for (int y = 0; y <= AIRGAP_QR_SIZE - 11; y++) {
            int a = 1, b = 1;
            for (int k = 0; k < 11; k++) {
                a &= m[y + k][x] == pat1[k];
                b &= m[y + k][x] == pat2[k];
            }
            if (a || b) score += 40;
        }
    }

    int dark = 0;
    for (int y = 0; y < AIRGAP_QR_SIZE; y++)
        for (int x = 0; x < AIRGAP_QR_SIZE; x++) dark += m[y][x] != 0U;
    int total = AIRGAP_QR_SIZE * AIRGAP_QR_SIZE;
    int percent = (dark * 100) / total;
    int deviation = percent > 50 ? percent - 50 : 50 - percent;
    score += (deviation / 5) * 10;
    return score;
}

int airgap_qr_encode_alphanumeric(const char *text, airgap_qr *out) {
    uint8_t data[QR_DATA_CODEWORDS];
    uint8_t ecc[QR_ECC_CODEWORDS];
    uint8_t codewords[QR_TOTAL_CODEWORDS];
    uint8_t modules[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE];
    uint8_t function[AIRGAP_QR_SIZE][AIRGAP_QR_SIZE];
    long best_score = 0;
    int best_mask = -1;

    if (text == NULL || out == NULL || !make_data_codewords(text, data)) return 0;
    rs_remainder(data, ecc);
    memcpy(codewords, data, QR_DATA_CODEWORDS);
    memcpy(codewords + QR_DATA_CODEWORDS, ecc, QR_ECC_CODEWORDS);

    for (int mask = 0; mask < 8; mask++) {
        draw_function_patterns(modules, function, mask);
        place_codewords(modules, function, codewords, mask);
        long s = penalty_score(modules);
        if (best_mask < 0 || s < best_score) {
            best_mask = mask;
            best_score = s;
            memcpy(out->module, modules, sizeof(out->module));
        }
    }

    memset(data, 0, sizeof(data));
    memset(ecc, 0, sizeof(ecc));
    memset(codewords, 0, sizeof(codewords));
    memset(modules, 0, sizeof(modules));
    memset(function, 0, sizeof(function));
    return best_mask >= 0;
}

static int stdout_is_terminal(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    return h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

static int terminal_columns(void) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &info))
        return (int)(info.srWindow.Right - info.srWindow.Left + 1);
    return 0;
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return (int)ws.ws_col;
    return 0;
#endif
}

#ifdef _WIN32
static int win_half_block(HANDLE h, WORD original, int top_dark, int bottom_dark) {
    const WORD white_fg = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    const WORD white_bg = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
    WORD attr = (top_dark ? 0 : white_fg) | (bottom_dark ? 0 : white_bg);
    wchar_t ch = 0x2580; /* U+2580 UPPER HALF BLOCK */
    DWORD written = 0;
    if (!SetConsoleTextAttribute(h, attr)) return 0;
    if (!WriteConsoleW(h, &ch, 1, &written, NULL) || written != 1) {
        (void)SetConsoleTextAttribute(h, original);
        return 0;
    }
    return 1;
}

static int win_write_w(HANDLE h, const wchar_t *text, DWORD len) {
    DWORD written = 0;
    return WriteConsoleW(h, text, len, &written, NULL) != 0 && written == len;
}

static int win_full_cell(HANDLE h, int dark) {
    const WORD white_bg = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
    if (!SetConsoleTextAttribute(h, dark ? 0 : white_bg)) return 0;
    return win_write_w(h, L"  ", 2);
}
#endif

static int module_with_quiet(const airgap_qr *qr, int x, int y) {
    x -= AIRGAP_QR_QUIET_ZONE;
    y -= AIRGAP_QR_QUIET_ZONE;
    if (x < 0 || y < 0 || x >= AIRGAP_QR_SIZE || y >= AIRGAP_QR_SIZE) return 0;
    return qr->module[y][x] != 0U;
}

int airgap_qr_print_terminal(const airgap_qr *qr) {
    if (qr == NULL || !stdout_is_terminal()) return 0;

    const int modules = AIRGAP_QR_SIZE + 2 * AIRGAP_QR_QUIET_ZONE;
    int cols = terminal_columns();
    if (cols > 0 && cols < modules) {
        fprintf(stderr, "[QR not rendered: terminal needs at least %d columns]\n", modules);
        return 0;
    }

    /*
     * Preferred renderer: U+2580 combines two vertical QR modules in one text
     * row. On typical terminal fonts this keeps modules close to square while
     * using only 37 columns x 19 rows for Version 3 plus quiet zone.
     */
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    fflush(stdout);
    if (h == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(h, &info)) return 0;
    WORD original = info.wAttributes;
    int unicode_ok = 1;

    for (int y = 0; y < modules && unicode_ok; y += 2) {
        for (int x = 0; x < modules; x++) {
            int top = module_with_quiet(qr, x, y);
            int bottom = (y + 1 < modules) ? module_with_quiet(qr, x, y + 1) : 0;
            if (!win_half_block(h, original, top, bottom)) {
                unicode_ok = 0;
                break;
            }
        }
        (void)SetConsoleTextAttribute(h, original);
        if (!win_write_w(h, L"\r\n", 2)) unicode_ok = 0;
    }
    (void)SetConsoleTextAttribute(h, original);

    if (!unicode_ok) {
        /* Legacy-console fallback: ASCII spaces with explicit backgrounds. */
        fputs("[Unicode QR unavailable; using full-cell fallback]\n", stdout);
        for (int y = 0; y < modules; y++) {
            for (int x = 0; x < modules; x++) {
                if (!win_full_cell(h, module_with_quiet(qr, x, y))) break;
            }
            (void)SetConsoleTextAttribute(h, original);
            (void)win_write_w(h, L"\r\n", 2);
        }
        (void)SetConsoleTextAttribute(h, original);
    }
#else
    static const char upper_half[] = "\xE2\x96\x80"; /* UTF-8 U+2580 */
    for (int y = 0; y < modules; y += 2) {
        for (int x = 0; x < modules; x++) {
            int top = module_with_quiet(qr, x, y);
            int bottom = (y + 1 < modules) ? module_with_quiet(qr, x, y + 1) : 0;
            if (top)
                fputs(bottom ? "\033[30;40m" : "\033[30;107m", stdout);
            else
                fputs(bottom ? "\033[97;40m" : "\033[97;107m", stdout);
            fputs(upper_half, stdout);
        }
        fputs("\033[0m\n", stdout);
    }
    fputs("\033[0m", stdout);
#endif
    fflush(stdout);
    return 1;
}
