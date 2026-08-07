/*
 * AirgapBip39.c - Deterministic BIP39 generator
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <secp256k1.h>

#include "wordlist.h"
#include "argon2.h"
#include "sha/sha256.h"
#include "sha/sha512.h"
#include "sha/hmac_sha512.h"
#include "sha/pbkdf2.h"
#include "qr/qr.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/random.h>
#endif
#endif

#define HARDENED 0x80000000U
#define GREEN    "\033[32m"
#define BLUE     "\033[34m"
#define RED      "\033[31m"
#define YELLOW   "\033[33m"
#define RESET    "\033[0m"
#define PROFILE_ID                  "AIRGAPBIP39-2SECRET-BIND-ARGON2ID-PWD-SECRET-AD-HKDFSHA512-8G-T3-P4-V2"
#define ARGON2_TIME_COST            UINT32_C(3)
#define ARGON2_MEMORY_KIB           UINT32_C(8388608) /* 8 GiB total memory */
#define ARGON2_LANES                UINT32_C(4)
#define ARGON2_OUT_BYTES            64U
#define PRIMARY_SECRET_MIN_LEN      12U
#define PRIMARY_SECRET_MAX_LEN      240U
#define SECONDARY_SECRET_MIN_LEN    12U
#define SECONDARY_SECRET_MAX_LEN    240U
#define MAX_WALLET_NUMBER           UINT32_C(1000000)
#define SECRET_REPEAT_ATTEMPTS      5U
#define PERSONAL_FIELD_MAX_LEN      80U

static const char DOMAIN_PUBLIC_CONTEXT[] =
    "AirgapBIP39/public-context/csn-dob-parents/lowercase-raw-date/v2";
static const char DOMAIN_ARGON_SALT[] =
    "AirgapBIP39/argon2-salt/profile-context-and-wallet/v2";
static const char DOMAIN_ARGON_AD[] =
    "AirgapBIP39/argon2-ad/profile-context-and-wallet/v2";
static const char DOMAIN_HKDF_EXTRACT[] =
    "AirgapBIP39/hkdf-extract/argon2id-v2";
static const char DOMAIN_SECRET_BINDING[] =
    "AirgapBIP39/secret-binding/primary-secondary/v2";
static const char DOMAIN_ENTROPY[] =
    "AirgapBIP39/bip39-entropy/24/argon2id-hkdf-sha512/v2";
static const char DOMAIN_RECOVERY_FP_KEY[] =
    "AirgapBIP39/recovery-fields-fingerprint/key";
static const char DOMAIN_RECOVERY_FP[] =
    "AirgapBIP39/recovery-fields-fingerprint/value";
static const char DOMAIN_WALLET_FINGERPRINT[] =
    "AirgapBIP39/wallet-address-fingerprint";

typedef struct {
    char citizen_service_number[PERSONAL_FIELD_MAX_LEN + 2U];
    char date_of_birth[16];
    char father_first_name[PERSONAL_FIELD_MAX_LEN + 2U];
    char mother_first_name[PERSONAL_FIELD_MAX_LEN + 2U];
} recovery_context;

static secp256k1_context *ctx = NULL;

#ifndef _WIN32
static struct termios saved_termios;
static int termios_saved = 0;
#else
static HANDLE saved_input_handle = INVALID_HANDLE_VALUE;
static DWORD saved_input_mode = 0;
static int input_mode_saved = 0;
#endif

/* ---------- Process / terminal hardening ---------- */
static void secure_wipe(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n-- != 0U) {
        *p++ = 0U;
    }
}

static int os_random_bytes(uint8_t *out, size_t n) {
#ifdef _WIN32
    if (n > (size_t)ULONG_MAX) return 0;
    return BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__linux__)
    size_t done = 0U;
    while (done < n) {
        ssize_t r = getrandom(out + done, n - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (r == 0) return 0;
        done += (size_t)r;
    }
    return 1;
#else
    arc4random_buf(out, n);
    return 1;
#endif
}

static int secure_argon_alloc(uint8_t **memory, size_t bytes) {
    if (memory == NULL || bytes == 0U) return -1;
    *memory = NULL;
#ifdef _WIN32
    void *p = VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL) return -1;
    (void)VirtualLock(p, bytes);
    *memory = (uint8_t *)p;
    return 0;
#else
    int flags = MAP_PRIVATE;
#ifdef MAP_ANONYMOUS
    flags |= MAP_ANONYMOUS;
#else
    flags |= MAP_ANON;
#endif
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) return -1;
#ifdef __linux__
#ifdef MADV_DONTDUMP
    (void)madvise(p, bytes, MADV_DONTDUMP);
#endif
#ifdef MADV_DONTFORK
    (void)madvise(p, bytes, MADV_DONTFORK);
#endif
#endif
    (void)mlock(p, bytes);
    *memory = (uint8_t *)p;
    return 0;
#endif
}

static void secure_argon_free(uint8_t *memory, size_t bytes) {
    if (memory == NULL || bytes == 0U) return;
#ifdef _WIN32
    (void)VirtualUnlock(memory, bytes);
    (void)VirtualFree(memory, 0, MEM_RELEASE);
#else
    (void)munlock(memory, bytes);
    (void)munmap(memory, bytes);
#endif
}

static void die(const char *msg) {
    fprintf(stderr, "%sError:%s %s\n", RED, RESET, msg);
    exit(EXIT_FAILURE);
}

static void enable_windows_ansi(void) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    (void)SetConsoleMode(hOut, mode);
#endif
}

static void restore_terminal_echo(void) {
#ifdef _WIN32
    if (input_mode_saved && saved_input_handle != INVALID_HANDLE_VALUE) {
        (void)SetConsoleMode(saved_input_handle, saved_input_mode);
        input_mode_saved = 0;
    }
#else
    if (termios_saved) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        termios_saved = 0;
    }
#endif
}

static int disable_terminal_echo(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) return 0;
    saved_input_handle = h;
    saved_input_mode = mode;
    input_mode_saved = 1;
    mode &= ~(ENABLE_ECHO_INPUT);
    if (!SetConsoleMode(h, mode)) {
        input_mode_saved = 0;
        return 0;
    }
    return 1;
#else
    struct termios t;
    if (!isatty(STDIN_FILENO)) return 0;
    if (tcgetattr(STDIN_FILENO, &saved_termios) != 0) return 0;
    termios_saved = 1;
    t = saved_termios;
    t.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0) {
        termios_saved = 0;
        return 0;
    }
    return 1;
#endif
}

static void disable_core_dumps(void) {
#ifndef _WIN32
    struct rlimit lim;
    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &lim) != 0) {
        fprintf(stderr, "%sWarning:%s could not disable core dumps.\n", YELLOW, RESET);
    }
#ifdef __linux__
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        fprintf(stderr, "%sWarning:%s could not mark process non-dumpable.\n", YELLOW, RESET);
    }
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
#endif
}

static int lock_secret_memory(void *p, size_t n) {
#ifdef _WIN32
    return VirtualLock(p, n) != 0;
#else
    return mlock(p, n) == 0;
#endif
}

static void unlock_secret_memory(void *p, size_t n) {
#ifdef _WIN32
    (void)VirtualUnlock(p, n);
#else
    (void)munlock(p, n);
#endif
}

static void warn_if_swap_active(void) {
#ifdef __linux__
    FILE *f = fopen("/proc/swaps", "r");
    if (f != NULL) {
        char line[512];
        int lines = 0;
        while (fgets(line, sizeof(line), f) != NULL) {
            lines++;
            if (lines > 1) {
                fprintf(stderr,
                    "%sWARNING:%s swap appears to be enabled. For maximum protection,\n"
                    "disable swap before entering secrets on the air-gapped machine.\n\n",
                    YELLOW, RESET);
                break;
            }
        }
        (void)fclose(f);
    }
#endif
}

/* ---------- Input handling ---------- */
static size_t trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0U && (s[n - 1U] == '\n' || s[n - 1U] == '\r')) {
        s[--n] = '\0';
    }
    return n;
}

static int is_portable_ascii(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20U || c > 0x7eU) return 0;
    }
    return 1;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0U;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0U;
}

static size_t read_hidden_line(const char *prompt, char *out, size_t outsz) {
    int echo_disabled;
    if (outsz < 2U) die("input buffer too small");

    fputs(prompt, stdout);
    fflush(stdout);

    echo_disabled = disable_terminal_echo();
    if (!echo_disabled) die("secure terminal input unavailable");
    if (fgets(out, (int)outsz, stdin) == NULL) {
        restore_terminal_echo();
        die("input read failed");
    }
    restore_terminal_echo();
    if (echo_disabled) fputc('\n', stdout);

    size_t raw_len = strlen(out);
    if (raw_len == outsz - 1U && out[raw_len - 1U] != '\n' && out[raw_len - 1U] != '\r') {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) { }
        secure_wipe(out, outsz);
        return SIZE_MAX;
    }
    return trim_newline(out);
}

static size_t read_visible_line(const char *prompt, char *out, size_t outsz) {
    if (outsz < 2U) die("input buffer too small");
    fputs(prompt, stdout);
    fflush(stdout);
    if (fgets(out, (int)outsz, stdin) == NULL) die("input read failed");

    size_t raw_len = strlen(out);
    if (raw_len == outsz - 1U && out[raw_len - 1U] != '\n' && out[raw_len - 1U] != '\r') {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) { }
        secure_wipe(out, outsz);
        return SIZE_MAX;
    }
    return trim_newline(out);
}

static int valid_secret_value(const char *s, size_t n,
                              size_t min_len, size_t max_len) {
    return n != SIZE_MAX && n >= min_len && n <= max_len && is_portable_ascii(s, n);
}

static size_t read_confirmed_secret(const char *label,
                                    char *out, size_t outsz,
                                    size_t min_len, size_t max_len) {
    char confirm[256];
    char prompt1[96];
    char prompt2[96];
    int confirm_locked;

    if (outsz > sizeof(confirm)) die("secret buffer configuration error");
    confirm_locked = lock_secret_memory(confirm, sizeof(confirm));
    if (!confirm_locked) die("secret confirmation memory lock failed");
    (void)snprintf(prompt1, sizeof(prompt1), "%s > ", label);
    (void)snprintf(prompt2, sizeof(prompt2), "Repeat %s > ", label);

    for (;;) {
        size_t n1;
        secure_wipe(out, outsz);
        secure_wipe(confirm, sizeof(confirm));

        n1 = read_hidden_line(prompt1, out, outsz);
        if (!valid_secret_value(out, n1, min_len, max_len)) {
            secure_wipe(out, outsz);
            fprintf(stderr,
                    "%sInvalid %s.%s Use %zu-%zu printable ASCII characters.\n\n",
                    YELLOW, label, RESET, min_len, max_len);
            continue;
        }

        for (unsigned attempt = 1U; attempt <= SECRET_REPEAT_ATTEMPTS; attempt++) {
            size_t n2;
            secure_wipe(confirm, sizeof(confirm));
            n2 = read_hidden_line(prompt2, confirm, sizeof(confirm));

            if (n2 != SIZE_MAX && n2 == n1 &&
                is_portable_ascii(confirm, n2) &&
                constant_time_equal((const uint8_t *)out,
                                    (const uint8_t *)confirm, n1)) {
                secure_wipe(confirm, sizeof(confirm));
                unlock_secret_memory(confirm, sizeof(confirm));
                printf("%s%s confirmed.%s\n\n", GREEN, label, RESET);
                return n1;
            }

            secure_wipe(confirm, sizeof(confirm));
            if (attempt < SECRET_REPEAT_ATTEMPTS) {
                fprintf(stderr,
                        "%sNo match.%s Repeat %s again (%u of %u attempts used).\n",
                        YELLOW, RESET, label, attempt, SECRET_REPEAT_ATTEMPTS);
            }
        }

        secure_wipe(out, outsz);
        fprintf(stderr,
                "%sFive repeat attempts did not match.%s\n"
                "Re-enter %s from the beginning.\n\n",
                YELLOW, RESET, label);
    }
}

static void ascii_lowercase_inplace(char *s) {
    if (s == NULL) return;
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') *s = (char)(c + ('a' - 'A'));
    }
}

static int is_leap_year(unsigned year) {
    return (year % 4U == 0U && year % 100U != 0U) || (year % 400U == 0U);
}

static int valid_calendar_date(unsigned day, unsigned month, unsigned year) {
    static const unsigned days_in_month[12] = {
        31U,28U,31U,30U,31U,30U,31U,31U,30U,31U,30U,31U
    };
    unsigned max_day;
    if (year < 1900U || year > 2100U || month < 1U || month > 12U || day < 1U)
        return 0;
    max_day = days_in_month[month - 1U];
    if (month == 2U && is_leap_year(year)) max_day = 29U;
    return day <= max_day;
}

static int parse_two_part_date(const char *s, size_t n,
                               unsigned *a, unsigned *b, unsigned *year) {
    if (n != 10U || s[2] != '-' || s[5] != '-') return 0;
    for (size_t i = 0; i < 10U; i++) {
        if (i == 2U || i == 5U) continue;
        if (s[i] < '0' || s[i] > '9') return 0;
    }
    *a = (unsigned)(s[0] - '0') * 10U + (unsigned)(s[1] - '0');
    *b = (unsigned)(s[3] - '0') * 10U + (unsigned)(s[4] - '0');
    *year = (unsigned)(s[6] - '0') * 1000U + (unsigned)(s[7] - '0') * 100U +
            (unsigned)(s[8] - '0') * 10U + (unsigned)(s[9] - '0');
    return 1;
}

static int valid_date_input(const char *s, size_t n) {
    unsigned a, b, year;
    if (!parse_two_part_date(s, n, &a, &b, &year)) return 0;
    return valid_calendar_date(a, b, year) || valid_calendar_date(b, a, year);
}

static size_t read_visible_lower_field(const char *prompt, char *out, size_t outsz,
                                       const char *field_name) {
    for (;;) {
        size_t n = read_visible_line(prompt, out, outsz);
        if (n != SIZE_MAX && n >= 1U && n <= PERSONAL_FIELD_MAX_LEN &&
            is_portable_ascii(out, n) && out[0] != ' ' && out[n - 1U] != ' ') {
            ascii_lowercase_inplace(out);
            return n;
        }
        secure_wipe(out, outsz);
        fprintf(stderr,
                "%sInvalid %s.%s Use 1-%u printable ASCII characters; "
                "no leading/trailing spaces.\n",
                YELLOW, field_name, RESET, (unsigned)PERSONAL_FIELD_MAX_LEN);
    }
}

static void read_recovery_context(recovery_context *rc) {
    (void)read_visible_lower_field(
        "Citizen Service Number > ",
        rc->citizen_service_number, sizeof(rc->citizen_service_number),
        "Citizen Service Number");

    for (;;) {
        size_t n = read_visible_line(
            "Date Of Birth [DD-MM-YYYY or MM-DD-YYYY] > ",
            rc->date_of_birth, sizeof(rc->date_of_birth));
        if (n != SIZE_MAX && valid_date_input(rc->date_of_birth, n)) break;
        secure_wipe(rc->date_of_birth, sizeof(rc->date_of_birth));
        fprintf(stderr,
                "%sInvalid date.%s Use a real date such as 31-12-2010 or 12-31-2010.\n",
                YELLOW, RESET);
    }

    (void)read_visible_lower_field("First Name Father > ",
                                   rc->father_first_name, sizeof(rc->father_first_name),
                                   "name");
    (void)read_visible_lower_field("First Name Mother > ",
                                   rc->mother_first_name, sizeof(rc->mother_first_name),
                                   "name");
}

static uint32_t read_wallet_number(void) {
    char buf[64];

    for (;;) {
        char *end = NULL;
        unsigned long v;
        size_t n = read_visible_line("Wallet number (0-1000000, default 1) > ",
                                     buf, sizeof(buf));
        if (n == 0U) {
            secure_wipe(buf, sizeof(buf));
            return 1U;
        }
        if (n == SIZE_MAX) {
            secure_wipe(buf, sizeof(buf));
            fprintf(stderr, "%sInvalid wallet number.%s\n", YELLOW, RESET);
            continue;
        }

        errno = 0;
        v = strtoul(buf, &end, 10);
        if (errno == 0 && end != buf && v <= (unsigned long)MAX_WALLET_NUMBER) {
            while (*end == ' ' || *end == '\t') end++;
            if (*end == '\0') {
                secure_wipe(buf, sizeof(buf));
                return (uint32_t)v;
            }
        }
        secure_wipe(buf, sizeof(buf));
        fprintf(stderr, "%sInvalid wallet number.%s Use 0-1000000.\n", YELLOW, RESET);
    }
}

static void store_be32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void tagged_hash(const char *tag,
                        const uint8_t *msg, size_t msglen,
                        uint8_t out[32]) {
    uint8_t tagh[32];
    uint8_t buf[96];
    size_t taglen = strlen(tag);

    if (msglen > 32U) die("tagged_hash message too large");
    sha256_hash((const uint8_t *)tag, taglen, tagh);
    memcpy(buf, tagh, 32);
    memcpy(buf + 32, tagh, 32);
    memcpy(buf + 64, msg, msglen);
    sha256_hash(buf, 64U + msglen, out);

    secure_wipe(tagh, sizeof(tagh));
    secure_wipe(buf, sizeof(buf));
}

/* ---------- BIP39 ---------- */
static void bip39_from_entropy_256(const uint8_t entropy[32],
                                   char *out, size_t outsz) {
    uint8_t hash[32];
    uint8_t data[33];
    size_t used = 0U;

    sha256_hash(entropy, 32, hash);
    memcpy(data, entropy, 32);
    data[32] = hash[0]; /* ENT/32 = 8 checksum bits */

    if (outsz == 0U) die("mnemonic buffer too small");
    out[0] = '\0';

    for (int w = 0; w < 24; w++) {
        unsigned idx = 0U;
        for (int j = 0; j < 11; j++) {
            size_t bitpos = (size_t)w * 11U + (size_t)j;
            size_t bytepos = bitpos / 8U;
            unsigned shift = 7U - (unsigned)(bitpos % 8U);
            idx = (idx << 1) | ((unsigned)(data[bytepos] >> shift) & 1U);
        }

        const char *word = wordlist[idx];
        size_t wl = strlen(word);
        size_t needed = wl + ((w == 0) ? 0U : 1U) + 1U;
        if (used + needed > outsz) die("mnemonic buffer too small");

        if (w != 0) out[used++] = ' ';
        memcpy(out + used, word, wl);
        used += wl;
        out[used] = '\0';
    }

    secure_wipe(hash, sizeof(hash));
    secure_wipe(data, sizeof(data));
}

static void print_mnemonic_cols(const char *mnemonic) {
    char copy[512];
    char *list[24];
    int count = 0;

    (void)snprintf(copy, sizeof(copy), "%s", mnemonic);
    char *tok = strtok(copy, " ");
    while (tok != NULL && count < 24) {
        list[count++] = tok;
        tok = strtok(NULL, " ");
    }
    if (count != 24) {
        secure_wipe(copy, sizeof(copy));
        die("internal mnemonic word count error");
    }

    for (int r = 0; r < 6; r++) {
        for (int c = 0; c < 4; c++) {
            int idx = r + c * 6;
            printf("%2d.%s%-12s%s  ", idx + 1, GREEN, list[idx], RESET);
        }
        fputc('\n', stdout);
    }
    secure_wipe(copy, sizeof(copy));
}

static void bip39_seed_no_passphrase(const char *mnemonic, uint8_t out[64]) {
    static const uint8_t salt[] = "mnemonic";
    if (pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic),
                           salt, sizeof(salt) - 1U,
                           2048U, out, 64U) != 0) {
        die("PBKDF2-HMAC-SHA512 failed");
    }
}

/* ---------- BIP32 ---------- */
typedef struct {
    uint8_t priv[32];
    uint8_t pub[33];
    uint8_t chain[32];
    uint32_t child_index;
} ext_key;

static void pubkey_from_priv(const uint8_t priv[32], uint8_t out33[33]) {
    secp256k1_pubkey pub;
    size_t len = 33U;

    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) die("pubkey_create failed");
    if (!secp256k1_ec_pubkey_serialize(ctx, out33, &len, &pub,
                                      SECP256K1_EC_COMPRESSED) || len != 33U) {
        secure_wipe(&pub, sizeof(pub));
        die("pubkey serialization failed");
    }
    secure_wipe(&pub, sizeof(pub));
}

static void bip32_from_seed(const uint8_t seed[64], ext_key *out) {
    static const uint8_t key[] = "Bitcoin seed";
    uint8_t I[64];

    hmac_sha512(key, sizeof(key) - 1U, seed, 64U, I);
    if (!secp256k1_ec_seckey_verify(ctx, I)) {
        secure_wipe(I, sizeof(I));
        die("BIP32 produced invalid master key");
    }

    memcpy(out->priv, I, 32);
    memcpy(out->chain, I + 32, 32);
    out->child_index = 0U;
    pubkey_from_priv(out->priv, out->pub);
    secure_wipe(I, sizeof(I));
}

static uint32_t bip32_ckd_priv(const ext_key *parent,
                               uint32_t requested_index,
                               ext_key *child) {
    uint32_t index = requested_index;
    uint8_t data[37];
    uint8_t I[64];

    for (;;) {
        size_t n = 0U;
        if ((index & HARDENED) != 0U) {
            data[n++] = 0U;
            memcpy(data + n, parent->priv, 32);
            n += 32U;
        } else {
            memcpy(data + n, parent->pub, 33);
            n += 33U;
        }
        data[n++] = (uint8_t)(index >> 24);
        data[n++] = (uint8_t)(index >> 16);
        data[n++] = (uint8_t)(index >> 8);
        data[n++] = (uint8_t)index;

        hmac_sha512(parent->chain, 32U, data, n, I);
        memcpy(child->priv, parent->priv, 32);

        if (secp256k1_ec_seckey_tweak_add(ctx, child->priv, I)) {
            memcpy(child->chain, I + 32, 32);
            child->child_index = index;
            pubkey_from_priv(child->priv, child->pub);
            secure_wipe(data, sizeof(data));
            secure_wipe(I, sizeof(I));
            return index;
        }

        if (index == UINT32_MAX) {
            secure_wipe(data, sizeof(data));
            secure_wipe(I, sizeof(I));
            die("BIP32 child derivation exhausted index range");
        }
        index++;
    }
}

/* ---------- BIP341 / BIP86 Taproot ---------- */
static void tap_output_key(const uint8_t pub33[33], uint8_t output_xonly[32]) {
    secp256k1_pubkey internal_pub;
    uint8_t internal_xonly[32];
    uint8_t tweak[32];
    uint8_t serialized[33];
    size_t serialized_len = sizeof(serialized);

    if (pub33[0] != 0x02U && pub33[0] != 0x03U)
        die("invalid compressed pubkey");
    if (!secp256k1_ec_pubkey_parse(ctx, &internal_pub, pub33, 33U))
        die("Taproot internal pubkey parse failed");

    memcpy(internal_xonly, pub33 + 1, sizeof(internal_xonly));

    /* BIP340/BIP341 x-only keys use the even-Y lift_x() representative. */
    if (pub33[0] == 0x03U && !secp256k1_ec_pubkey_negate(ctx, &internal_pub))
        die("Taproot internal-key normalization failed");

    tagged_hash("TapTweak", internal_xonly, sizeof(internal_xonly), tweak);
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &internal_pub, tweak)) {
        secure_wipe(internal_xonly, sizeof(internal_xonly));
        secure_wipe(tweak, sizeof(tweak));
        die("Taproot public-key tweak failed");
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len,
                                      &internal_pub, SECP256K1_EC_COMPRESSED) ||
        serialized_len != sizeof(serialized)) {
        secure_wipe(internal_xonly, sizeof(internal_xonly));
        secure_wipe(tweak, sizeof(tweak));
        die("Taproot output-key serialization failed");
    }

    memcpy(output_xonly, serialized + 1, 32U);
    secure_wipe(internal_xonly, sizeof(internal_xonly));
    secure_wipe(tweak, sizeof(tweak));
    secure_wipe(serialized, sizeof(serialized));
    secure_wipe(&internal_pub, sizeof(internal_pub));
}

/* ---------- Bech32m for P2TR ---------- */
static uint32_t bech32_polymod(const uint8_t *v, size_t n) {
    static const uint32_t GEN[5] = {
        UINT32_C(0x3b6a57b2), UINT32_C(0x26508e6d), UINT32_C(0x1ea119fa),
        UINT32_C(0x3d4233dd), UINT32_C(0x2a1462b3)
    };
    uint32_t chk = 1U;

    for (size_t i = 0; i < n; i++) {
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & UINT32_C(0x1ffffff)) << 5) ^ (uint32_t)v[i];
        for (unsigned j = 0; j < 5U; j++) {
            if (((top >> j) & 1U) != 0U) chk ^= GEN[j];
        }
    }
    return chk;
}

static size_t hrp_expand(const char *hrp, uint8_t *out, size_t outcap) {
    size_t n = strlen(hrp);
    if (outcap < n * 2U + 1U) die("hrp buffer too small");
    size_t p = 0U;
    for (size_t i = 0; i < n; i++) out[p++] = (uint8_t)((unsigned char)hrp[i] >> 5);
    out[p++] = 0U;
    for (size_t i = 0; i < n; i++) out[p++] = (uint8_t)((unsigned char)hrp[i] & 31U);
    return p;
}

static int convert_bits_8_to_5(const uint8_t *in, size_t inlen,
                               uint8_t *out, size_t outcap,
                               size_t *outlen) {
    uint32_t acc = 0U;
    unsigned bits = 0U;
    size_t p = 0U;
    const uint32_t max_acc = (UINT32_C(1) << 12) - 1U; /* from+to-1 = 12 */

    for (size_t i = 0; i < inlen; i++) {
        acc = ((acc << 8) | (uint32_t)in[i]) & max_acc;
        bits += 8U;
        while (bits >= 5U) {
            bits -= 5U;
            if (p >= outcap) return 0;
            out[p++] = (uint8_t)((acc >> bits) & 31U);
        }
    }
    if (bits != 0U) {
        if (p >= outcap) return 0;
        out[p++] = (uint8_t)((acc << (5U - bits)) & 31U);
    }
    *outlen = p;
    return 1;
}

static void bech32m_encode_p2tr(const uint8_t xonly[32],
                                char *out, size_t outsz) {
    static const char *HRP = "bc";
    static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint8_t conv[64];
    uint8_t data[1 + 64];
    uint8_t hrpe[16];
    uint8_t vals[128];
    uint8_t checksum[6];
    size_t conv_len = 0U, data_len, hrp_len, vlen = 0U, pos = 0U;

    if (!convert_bits_8_to_5(xonly, 32U, conv, sizeof(conv), &conv_len))
        die("convertbits failed");

    data[0] = 1U; /* SegWit v1 */
    memcpy(data + 1, conv, conv_len);
    data_len = 1U + conv_len;

    hrp_len = hrp_expand(HRP, hrpe, sizeof(hrpe));
    if (hrp_len + data_len + 6U > sizeof(vals)) die("bech32 internal buffer too small");
    memcpy(vals + vlen, hrpe, hrp_len); vlen += hrp_len;
    memcpy(vals + vlen, data, data_len); vlen += data_len;
    memset(vals + vlen, 0, 6U); vlen += 6U;

    uint32_t pm = bech32_polymod(vals, vlen) ^ UINT32_C(0x2bc830a3);
    for (int i = 0; i < 6; i++) checksum[i] = (uint8_t)((pm >> (5 * (5 - i))) & 31U);

    if (outsz < 4U + data_len + 6U) die("address buffer too small");
    out[pos++] = 'b'; out[pos++] = 'c'; out[pos++] = '1';
    for (size_t i = 0; i < data_len; i++) out[pos++] = CHARSET[data[i]];
    for (size_t i = 0; i < 6U; i++) out[pos++] = CHARSET[checksum[i]];
    out[pos] = '\0';

    secure_wipe(conv, sizeof(conv));
    secure_wipe(data, sizeof(data));
    secure_wipe(hrpe, sizeof(hrpe));
    secure_wipe(vals, sizeof(vals));
    secure_wipe(checksum, sizeof(checksum));
}

/* ---------- Fixed input -> 256-bit BIP39 entropy ---------- */
static void append_framed_field(uint8_t *buf, size_t bufsz, size_t *p,
                                const char *value, size_t value_len) {
    uint8_t be_len[4];
    if (*p + 4U + value_len > bufsz) die("public context framing overflow");
    store_be32(be_len, (uint32_t)value_len);
    memcpy(buf + *p, be_len, sizeof(be_len)); *p += sizeof(be_len);
    memcpy(buf + *p, value, value_len); *p += value_len;
    secure_wipe(be_len, sizeof(be_len));
}

static void build_public_context_digest(const recovery_context *rc, uint8_t out[32]) {
    uint8_t buf[512];
    size_t p = 0U;
    size_t label_len = strlen(DOMAIN_PUBLIC_CONTEXT);
    size_t csn_len = strlen(rc->citizen_service_number);
    size_t dob_len = strlen(rc->date_of_birth);
    size_t father_len = strlen(rc->father_first_name);
    size_t mother_len = strlen(rc->mother_first_name);

    if (label_len > sizeof(buf)) die("public context domain too large");
    memcpy(buf + p, DOMAIN_PUBLIC_CONTEXT, label_len); p += label_len;
    append_framed_field(buf, sizeof(buf), &p, rc->citizen_service_number, csn_len);
    append_framed_field(buf, sizeof(buf), &p, rc->date_of_birth, dob_len);
    append_framed_field(buf, sizeof(buf), &p, rc->father_first_name, father_len);
    append_framed_field(buf, sizeof(buf), &p, rc->mother_first_name, mother_len);

    sha256_hash(buf, p, out);
    secure_wipe(buf, sizeof(buf));
}

static void derive_wallet_address_fingerprint(const char *address, uint8_t out[8]) {
    uint8_t buf[256];
    uint8_t digest[32];
    size_t label_len = strlen(DOMAIN_WALLET_FINGERPRINT);
    size_t address_len = strlen(address);
    if (label_len + address_len > sizeof(buf)) die("wallet fingerprint framing overflow");
    memcpy(buf, DOMAIN_WALLET_FINGERPRINT, label_len);
    memcpy(buf + label_len, address, address_len);
    sha256_hash(buf, label_len + address_len, digest);
    memcpy(out, digest, 8U);
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));
}

static void print_fingerprint64(const char *label, const uint8_t fp[8]) {
    printf("%s: ", label);
    for (size_t i = 0; i < 8U; i++) {
        printf("%02X", fp[i]);
        if (i == 1U || i == 3U || i == 5U) fputc('-', stdout);
    }
    fputc('\n', stdout);
}

static void derive_secret_binding(const char *primary, size_t primary_len,
                                  const char *secondary, size_t secondary_len,
                                  uint8_t out[64]) {
    sha512_ctx h;
    uint8_t be_primary[4], be_secondary[4];
    size_t label_len = strlen(DOMAIN_SECRET_BINDING);

    if (primary_len > PRIMARY_SECRET_MAX_LEN) die("primary secret too large");
    if (secondary_len > SECONDARY_SECRET_MAX_LEN) die("secondary secret too large");
    store_be32(be_primary, (uint32_t)primary_len);
    store_be32(be_secondary, (uint32_t)secondary_len);

    if (sha512_init(&h) != 0) die("secret binding init failed");
    if (sha512_update(&h, (const uint8_t *)DOMAIN_SECRET_BINDING, label_len) != 0 ||
        sha512_update(&h, be_primary, sizeof(be_primary)) != 0 ||
        sha512_update(&h, (const uint8_t *)primary, primary_len) != 0 ||
        sha512_update(&h, be_secondary, sizeof(be_secondary)) != 0 ||
        sha512_update(&h, (const uint8_t *)secondary, secondary_len) != 0 ||
        sha512_final(&h, out) != 0) {
        secure_wipe(&h, sizeof(h));
        secure_wipe(be_primary, sizeof(be_primary));
        secure_wipe(be_secondary, sizeof(be_secondary));
        die("secret binding failed");
    }

    secure_wipe(&h, sizeof(h));
    secure_wipe(be_primary, sizeof(be_primary));
    secure_wipe(be_secondary, sizeof(be_secondary));
}

static void derive_argon_salt(const uint8_t context_digest[32],
                              uint32_t wallet_num, uint8_t out[32]) {
    uint8_t buf[320];
    uint8_t be_wallet[4], be_profile_len[4], be_context_len[4];
    size_t label_len = strlen(DOMAIN_ARGON_SALT);
    size_t profile_len = strlen(PROFILE_ID);
    size_t p = 0U;

    if (label_len + 4U + profile_len + 4U + 32U + 4U > sizeof(buf))
        die("argon salt framing overflow");

    store_be32(be_profile_len, (uint32_t)profile_len);
    store_be32(be_context_len, 32U);
    store_be32(be_wallet, wallet_num);

    memcpy(buf + p, DOMAIN_ARGON_SALT, label_len); p += label_len;
    memcpy(buf + p, be_profile_len, sizeof(be_profile_len)); p += sizeof(be_profile_len);
    memcpy(buf + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(buf + p, be_context_len, sizeof(be_context_len)); p += sizeof(be_context_len);
    memcpy(buf + p, context_digest, 32U); p += 32U;
    memcpy(buf + p, be_wallet, sizeof(be_wallet)); p += sizeof(be_wallet);

    sha256_hash(buf, p, out);

    secure_wipe(buf, sizeof(buf));
    secure_wipe(be_wallet, sizeof(be_wallet));
    secure_wipe(be_profile_len, sizeof(be_profile_len));
    secure_wipe(be_context_len, sizeof(be_context_len));
}

static void derive_argon_ad(const uint8_t context_digest[32],
                            uint32_t wallet_num, uint8_t out[64]) {
    uint8_t buf[384];
    uint8_t be_wallet[4], be_profile_len[4], be_context_len[4];
    size_t label_len = strlen(DOMAIN_ARGON_AD);
    size_t profile_len = strlen(PROFILE_ID);
    size_t p = 0U;

    if (label_len + 4U + profile_len + 4U + 32U + 4U > sizeof(buf))
        die("argon associated-data framing overflow");

    store_be32(be_profile_len, (uint32_t)profile_len);
    store_be32(be_context_len, 32U);
    store_be32(be_wallet, wallet_num);

    memcpy(buf + p, DOMAIN_ARGON_AD, label_len); p += label_len;
    memcpy(buf + p, be_profile_len, sizeof(be_profile_len)); p += sizeof(be_profile_len);
    memcpy(buf + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(buf + p, be_context_len, sizeof(be_context_len)); p += sizeof(be_context_len);
    memcpy(buf + p, context_digest, 32U); p += 32U;
    memcpy(buf + p, be_wallet, sizeof(be_wallet)); p += sizeof(be_wallet);

    sha512_hash(buf, p, out);

    secure_wipe(buf, sizeof(buf));
    secure_wipe(be_wallet, sizeof(be_wallet));
    secure_wipe(be_profile_len, sizeof(be_profile_len));
    secure_wipe(be_context_len, sizeof(be_context_len));
}

/* HKDF-SHA512 key schedule over the Argon2id output. */
static void derive_post_argon_keys(const uint8_t master[64],
                                   const uint8_t secret_binding[64],
                                   const uint8_t argon_salt[32],
                                   const uint8_t argon_ad[64],
                                   const uint8_t context_digest[32],
                                   uint32_t wallet_num,
                                   uint8_t entropy[32],
                                   uint8_t recovery_fields_fp[8]) {
    uint8_t extract_salt[64];
    uint8_t bound_master[64];
    uint8_t prk[64];
    uint8_t entropy_block[64];
    uint8_t fp_key[64];
    uint8_t fp_block[64];
    uint8_t info[512];
    uint8_t be_wallet[4];
    size_t p = 0U;
    size_t profile_len = strlen(PROFILE_ID);
    size_t extract_domain_len = strlen(DOMAIN_HKDF_EXTRACT);
    size_t entropy_domain_len = strlen(DOMAIN_ENTROPY);
    size_t fp_key_domain_len = strlen(DOMAIN_RECOVERY_FP_KEY);
    size_t fp_domain_len = strlen(DOMAIN_RECOVERY_FP);

    store_be32(be_wallet, wallet_num);

    if (extract_domain_len + profile_len + 32U + 64U + 32U + sizeof(be_wallet) > sizeof(info))
        die("HKDF extract framing overflow");
    memcpy(info + p, DOMAIN_HKDF_EXTRACT, extract_domain_len); p += extract_domain_len;
    memcpy(info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(info + p, argon_salt, 32U); p += 32U;
    memcpy(info + p, argon_ad, 64U); p += 64U;
    memcpy(info + p, context_digest, 32U); p += 32U;
    memcpy(info + p, be_wallet, sizeof(be_wallet)); p += sizeof(be_wallet);
    sha512_hash(info, p, extract_salt);
    hmac_sha512(secret_binding, 64U, master, 64U, bound_master);
    hmac_sha512(extract_salt, sizeof(extract_salt), bound_master, sizeof(bound_master), prk);

    secure_wipe(info, sizeof(info));
    p = 0U;
    if (entropy_domain_len + profile_len + 64U + 32U + sizeof(be_wallet) + 1U > sizeof(info))
        die("entropy HKDF info overflow");
    memcpy(info + p, DOMAIN_ENTROPY, entropy_domain_len); p += entropy_domain_len;
    memcpy(info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(info + p, argon_ad, 64U); p += 64U;
    memcpy(info + p, context_digest, 32U); p += 32U;
    memcpy(info + p, be_wallet, sizeof(be_wallet)); p += sizeof(be_wallet);
    info[p++] = 0x01U;
    hmac_sha512(prk, sizeof(prk), info, p, entropy_block);
    memcpy(entropy, entropy_block, 32U);

    secure_wipe(info, sizeof(info));
    p = 0U;
    if (fp_key_domain_len + profile_len + 64U + 32U + sizeof(be_wallet) + 1U > sizeof(info))
        die("fingerprint key info overflow");
    memcpy(info + p, DOMAIN_RECOVERY_FP_KEY, fp_key_domain_len); p += fp_key_domain_len;
    memcpy(info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(info + p, argon_ad, 64U); p += 64U;
    memcpy(info + p, context_digest, 32U); p += 32U;
    memcpy(info + p, be_wallet, sizeof(be_wallet)); p += sizeof(be_wallet);
    info[p++] = 0x01U;
    hmac_sha512(prk, sizeof(prk), info, p, fp_key);

    secure_wipe(info, sizeof(info));
    p = 0U;
    if (fp_domain_len + 32U > sizeof(info)) die("fingerprint value info overflow");
    memcpy(info + p, DOMAIN_RECOVERY_FP, fp_domain_len); p += fp_domain_len;
    memcpy(info + p, context_digest, 32U); p += 32U;
    hmac_sha512(fp_key, sizeof(fp_key), info, p, fp_block);
    memcpy(recovery_fields_fp, fp_block, 8U);

    secure_wipe(extract_salt, sizeof(extract_salt));
    secure_wipe(bound_master, sizeof(bound_master));
    secure_wipe(prk, sizeof(prk));
    secure_wipe(entropy_block, sizeof(entropy_block));
    secure_wipe(fp_key, sizeof(fp_key));
    secure_wipe(fp_block, sizeof(fp_block));
    secure_wipe(info, sizeof(info));
    secure_wipe(be_wallet, sizeof(be_wallet));
}

static void derive_bip39_entropy(char *primary, size_t primary_len,
                                 char *secondary, size_t secondary_len,
                                 const uint8_t context_digest[32],
                                 uint32_t wallet_num,
                                 uint8_t entropy[32],
                                 uint8_t recovery_fields_fp[8]) {
    uint8_t argon_salt[32];
    uint8_t argon_ad[64];
    uint8_t secret_binding[64];
    uint8_t master[ARGON2_OUT_BYTES];
    argon2_context a2;
    int binding_locked = lock_secret_memory(secret_binding, sizeof(secret_binding));
    int master_locked = lock_secret_memory(master, sizeof(master));

    if (!binding_locked || !master_locked) {
        secure_wipe(primary, primary_len);
        secure_wipe(secondary, secondary_len);
        secure_wipe(secret_binding, sizeof(secret_binding));
        secure_wipe(master, sizeof(master));
        if (master_locked) unlock_secret_memory(master, sizeof(master));
        if (binding_locked) unlock_secret_memory(secret_binding, sizeof(secret_binding));
        die("KDF secret memory lock failed");
    }

    derive_secret_binding(primary, primary_len, secondary, secondary_len, secret_binding);
    derive_argon_salt(context_digest, wallet_num, argon_salt);
    derive_argon_ad(context_digest, wallet_num, argon_ad);

    memset(&a2, 0, sizeof(a2));
    a2.out = master;
    a2.outlen = (uint32_t)sizeof(master);
    a2.pwd = (uint8_t *)primary;
    a2.pwdlen = (uint32_t)primary_len;
    a2.salt = argon_salt;
    a2.saltlen = (uint32_t)sizeof(argon_salt);
    a2.secret = (uint8_t *)secondary;
    a2.secretlen = (uint32_t)secondary_len;
    a2.ad = argon_ad;
    a2.adlen = (uint32_t)sizeof(argon_ad);
    a2.t_cost = ARGON2_TIME_COST;
    a2.m_cost = ARGON2_MEMORY_KIB;
    a2.lanes = ARGON2_LANES;
    a2.threads = ARGON2_LANES;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;

    printf("\n[%s Argon2id started: 8 GiB, t=3, p=4 %s]\n", BLUE, RESET);
    fflush(stdout);

    int rc = argon2id_ctx(&a2);
    secure_wipe(primary, primary_len);
    secure_wipe(secondary, secondary_len);
    if (rc != ARGON2_OK) {
        secure_wipe(argon_salt, sizeof(argon_salt));
        secure_wipe(argon_ad, sizeof(argon_ad));
        secure_wipe(secret_binding, sizeof(secret_binding));
        secure_wipe(master, sizeof(master));
        unlock_secret_memory(master, sizeof(master));
        unlock_secret_memory(secret_binding, sizeof(secret_binding));
        die(argon2_error_message(rc));
    }

    derive_post_argon_keys(master, secret_binding, argon_salt, argon_ad, context_digest, wallet_num,
                           entropy, recovery_fields_fp);

    secure_wipe(argon_salt, sizeof(argon_salt));
    secure_wipe(argon_ad, sizeof(argon_ad));
    secure_wipe(secret_binding, sizeof(secret_binding));
    secure_wipe(master, sizeof(master));
    unlock_secret_memory(master, sizeof(master));
    unlock_secret_memory(secret_binding, sizeof(secret_binding));
}

/* ---------- Self-tests ---------- */
static int selftest_wordlist(void) {
    static const uint8_t expected[32] = {
        0x2f,0x5e,0xed,0x53,0xa4,0x72,0x7b,0x4b,
        0xf8,0x88,0x0d,0x8f,0x3f,0x19,0x9e,0xfc,
        0x90,0xe5,0x85,0x03,0x64,0x6d,0x9f,0xf8,
        0xef,0xf3,0xa2,0xed,0x3b,0x24,0xdb,0xda
    };
    uint8_t digest[32];
    uint8_t buf[16384];
    size_t p = 0U;

    for (size_t i = 0; i < 2048U; i++) {
        size_t n = strlen(wordlist[i]);
        if (n == 0U || p + n + 1U > sizeof(buf)) return 0;
        memcpy(buf + p, wordlist[i], n);
        p += n;
        buf[p++] = '\n';
    }
    sha256_hash(buf, p, digest);
    int ok = constant_time_equal(digest, expected, sizeof(digest));
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));
    return ok;
}

static int selftest_bip39(void) {
    uint8_t entropy[32] = {0};
    char mnemonic[512];
    static const char *expected =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon art";

    bip39_from_entropy_256(entropy, mnemonic, sizeof(mnemonic));
    int ok = strcmp(mnemonic, expected) == 0;
    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(mnemonic, sizeof(mnemonic));
    return ok;
}

static int selftest_input_framing(void) {
    static const uint8_t expected_binding[64] = { 0x3c,0x3b,0xa2,0x9b,0xa8,0xd8,0xd4,0x12,0x7c,0x29,0xf1,0xc1,0x4c,0x1e,0x6b,0x5e,0x22,0xdd,0xaf,0x3c,0xaf,0xb2,0x86,0xa0,0x51,0x58,0xa7,0x16,0x08,0x39,0x16,0x17,0x32,0x9b,0x65,0x6d,0x7b,0xf4,0x85,0x62,0xf6,0x48,0x9c,0x67,0x28,0xd4,0x2c,0x1e,0x0c,0x6d,0x41,0x8f,0x7c,0xae,0x36,0x30,0x04,0x66,0x5e,0x3a,0xf0,0xee,0x1f,0xe9 };
    static const uint8_t expected_context[32] = { 0xbd,0x80,0x6c,0x31,0x02,0x91,0x26,0xa0,0x69,0x15,0xab,0x79,0x5e,0x76,0xc3,0xdf,0xcd,0xdf,0xa8,0xfb,0xe2,0x71,0x5b,0x48,0x41,0x9c,0x9b,0xc9,0x43,0x64,0xad,0x7a };
    static const uint8_t expected_context_alt[32] = { 0x7c,0x93,0x0a,0x74,0x18,0xd2,0xfa,0x92,0xad,0x95,0x85,0x24,0xc5,0x8a,0x07,0x1d,0x13,0x8c,0x61,0x4e,0x9f,0x0d,0x3b,0x2d,0x13,0x67,0x3a,0xd0,0xfd,0x4e,0x44,0x24 };
    static const uint8_t expected_salt[32] = { 0xba,0x8c,0x4c,0xba,0x47,0xdf,0x1c,0x15,0xb8,0x73,0xec,0x42,0x85,0xe6,0xee,0x5e,0x9f,0xf8,0xe5,0xdf,0x38,0x7d,0x97,0xaa,0xee,0x97,0x06,0xb8,0x75,0x02,0x28,0x50 };
    static const uint8_t expected_ad[64] = { 0x91,0x13,0x3b,0x60,0x0d,0x03,0x74,0x77,0x48,0x11,0xa7,0x6c,0x4b,0xdc,0x5c,0x8a,0x17,0xb7,0x09,0x84,0x25,0x9a,0xfa,0x5b,0x3a,0x52,0x09,0x20,0xd2,0xa7,0xbe,0x49,0xe6,0x96,0x54,0xbc,0x52,0x8a,0x78,0x7c,0x86,0xf4,0x74,0xcf,0x9f,0x61,0xd6,0x02,0x22,0xd1,0x6f,0x57,0x85,0xd5,0xe9,0xd1,0xf1,0x9f,0xf1,0x60,0xd5,0x35,0x35,0x11 };
    static const uint8_t expected_entropy[32] = { 0x11,0x4b,0x27,0x2b,0x16,0x41,0x5e,0xf5,0xa8,0xdd,0xbf,0x4d,0x04,0x94,0xc8,0x63,0xcd,0x36,0xc7,0xd1,0xab,0x34,0x0f,0x46,0xbf,0x0c,0x86,0x26,0x43,0x18,0x2e,0xb2 };
    static const uint8_t expected_recovery_fp[8] = { 0x32,0x2e,0x9f,0x87,0xca,0x03,0x67,0x2d };
    static const uint8_t expected_wallet_fp[8] = { 0x3d,0xd3,0xab,0xc0,0xb7,0x4d,0xbf,0xf9 };
    static const char *test_address =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    char primary[13];
    char secondary[13];
    recovery_context rc = {{0},{0},{0},{0}};
    recovery_context rc_alt = {{0},{0},{0},{0}};
    uint8_t secret_binding[64];
    uint8_t context_digest[32];
    uint8_t context_digest_alt[32];
    uint8_t argon_salt[32];
    uint8_t argon_ad[64];
    uint8_t synthetic_master[64];
    uint8_t entropy[32];
    uint8_t recovery_fp[8];
    uint8_t wallet_fp[8];
    int ok;

    memset(primary, 'A', 12U); primary[12] = '\0';
    memset(secondary, 'B', 12U); secondary[12] = '\0';
    (void)snprintf(rc.citizen_service_number, sizeof(rc.citizen_service_number), "%s", "ID-Ab12-XY");
    (void)snprintf(rc.date_of_birth, sizeof(rc.date_of_birth), "%s", "10-03-1988");
    (void)snprintf(rc.father_first_name, sizeof(rc.father_first_name), "%s", "John");
    (void)snprintf(rc.mother_first_name, sizeof(rc.mother_first_name), "%s", "JANE");
    rc_alt = rc;
    (void)snprintf(rc_alt.date_of_birth, sizeof(rc_alt.date_of_birth), "%s", "03-10-1988");
    ascii_lowercase_inplace(rc.citizen_service_number);
    ascii_lowercase_inplace(rc.father_first_name);
    ascii_lowercase_inplace(rc.mother_first_name);
    ascii_lowercase_inplace(rc_alt.citizen_service_number);
    ascii_lowercase_inplace(rc_alt.father_first_name);
    ascii_lowercase_inplace(rc_alt.mother_first_name);
    if (!valid_date_input(rc.date_of_birth, strlen(rc.date_of_birth)) ||
        !valid_date_input(rc_alt.date_of_birth, strlen(rc_alt.date_of_birth))) {
        secure_wipe(primary, sizeof(primary));
        secure_wipe(secondary, sizeof(secondary));
        secure_wipe(&rc, sizeof(rc));
        secure_wipe(&rc_alt, sizeof(rc_alt));
        return 0;
    }
    if (strcmp(rc.citizen_service_number, "id-ab12-xy") != 0 ||
        strcmp(rc.date_of_birth, "10-03-1988") != 0 ||
        strcmp(rc.father_first_name, "john") != 0 ||
        strcmp(rc.mother_first_name, "jane") != 0 ||
        strcmp(rc_alt.date_of_birth, "03-10-1988") != 0) {
        secure_wipe(primary, sizeof(primary));
        secure_wipe(secondary, sizeof(secondary));
        secure_wipe(&rc, sizeof(rc));
        secure_wipe(&rc_alt, sizeof(rc_alt));
        return 0;
    }
    for (size_t i = 0; i < sizeof(synthetic_master); i++) synthetic_master[i] = (uint8_t)i;

    derive_secret_binding(primary, 12U, secondary, 12U, secret_binding);
    build_public_context_digest(&rc, context_digest);
    build_public_context_digest(&rc_alt, context_digest_alt);
    derive_argon_salt(context_digest, 42U, argon_salt);
    derive_argon_ad(context_digest, 42U, argon_ad);
    derive_post_argon_keys(synthetic_master, secret_binding, argon_salt, argon_ad, context_digest, 42U,
                           entropy, recovery_fp);
    derive_wallet_address_fingerprint(test_address, wallet_fp);

    ok = constant_time_equal(secret_binding, expected_binding, sizeof(expected_binding)) &&
         constant_time_equal(context_digest, expected_context, sizeof(expected_context)) &&
         constant_time_equal(context_digest_alt, expected_context_alt, sizeof(expected_context_alt)) &&
         !constant_time_equal(context_digest, context_digest_alt, sizeof(context_digest)) &&
         constant_time_equal(argon_salt, expected_salt, sizeof(expected_salt)) &&
         constant_time_equal(argon_ad, expected_ad, sizeof(expected_ad)) &&
         constant_time_equal(entropy, expected_entropy, sizeof(expected_entropy)) &&
         constant_time_equal(recovery_fp, expected_recovery_fp, sizeof(expected_recovery_fp)) &&
         constant_time_equal(wallet_fp, expected_wallet_fp, sizeof(expected_wallet_fp));

    secure_wipe(primary, sizeof(primary));
    secure_wipe(secondary, sizeof(secondary));
    secure_wipe(&rc, sizeof(rc));
    secure_wipe(&rc_alt, sizeof(rc_alt));
    secure_wipe(secret_binding, sizeof(secret_binding));
    secure_wipe(context_digest, sizeof(context_digest));
    secure_wipe(context_digest_alt, sizeof(context_digest_alt));
    secure_wipe(argon_salt, sizeof(argon_salt));
    secure_wipe(argon_ad, sizeof(argon_ad));
    secure_wipe(synthetic_master, sizeof(synthetic_master));
    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(recovery_fp, sizeof(recovery_fp));
    secure_wipe(wallet_fp, sizeof(wallet_fp));
    return ok;
}

static int selftest_argon2id(void) {
    uint8_t pwd[32], salt[16], secret[16], ad[12], out[32];
    static const uint8_t expected[32] = { 0x63,0xa6,0x63,0x4b,0x43,0x97,0xb5,0x60,0x21,0xbd,0xab,0xe1,0x22,0xa0,0x74,0x30,0x4c,0x2e,0xf9,0xe9,0x56,0xaa,0x1b,0xbe,0x0e,0x05,0x5a,0xd8,0x38,0xff,0x82,0xe3 };
    argon2_context a2;
    memset(pwd, 0x01, sizeof(pwd));
    memset(salt, 0x02, sizeof(salt));
    memset(secret, 0x03, sizeof(secret));
    memset(ad, 0x04, sizeof(ad));
    memset(&a2, 0, sizeof(a2));
    a2.out = out;
    a2.outlen = (uint32_t)sizeof(out);
    a2.pwd = pwd;
    a2.pwdlen = (uint32_t)sizeof(pwd);
    a2.salt = salt;
    a2.saltlen = (uint32_t)sizeof(salt);
    a2.secret = secret;
    a2.secretlen = (uint32_t)sizeof(secret);
    a2.ad = ad;
    a2.adlen = (uint32_t)sizeof(ad);
    a2.t_cost = 3U;
    a2.m_cost = 32U;
    a2.lanes = 4U;
    a2.threads = 4U;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = 0U;

    int rc = argon2id_ctx(&a2);
    int ok = (rc == ARGON2_OK) && constant_time_equal(out, expected, sizeof(out));
    secure_wipe(pwd, sizeof(pwd));
    secure_wipe(salt, sizeof(salt));
    secure_wipe(secret, sizeof(secret));
    secure_wipe(ad, sizeof(ad));
    secure_wipe(out, sizeof(out));
    return ok;
}

static int selftest_bip86(void) {
    static const char *mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    static const char *expected0 =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    static const char *expected1 =
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh";

    uint8_t seed[64];
    ext_key master, p86, c86, a86, base, addr;
    uint8_t xonly[32];
    char address[128];
    int ok = 1;

    memset(&master, 0, sizeof(master));
    memset(&p86, 0, sizeof(p86));
    memset(&c86, 0, sizeof(c86));
    memset(&a86, 0, sizeof(a86));
    memset(&base, 0, sizeof(base));
    memset(&addr, 0, sizeof(addr));

    bip39_seed_no_passphrase(mnemonic, seed);
    bip32_from_seed(seed, &master);
    (void)bip32_ckd_priv(&master, 86U | HARDENED, &p86);
    (void)bip32_ckd_priv(&p86, 0U | HARDENED, &c86);
    (void)bip32_ckd_priv(&c86, 0U | HARDENED, &a86);
    (void)bip32_ckd_priv(&a86, 0U, &base);

    (void)bip32_ckd_priv(&base, 0U, &addr);
    tap_output_key(addr.pub, xonly);
    bech32m_encode_p2tr(xonly, address, sizeof(address));
    if (strcmp(address, expected0) != 0) ok = 0;
    secure_wipe(&addr, sizeof(addr));
    secure_wipe(xonly, sizeof(xonly));
    secure_wipe(address, sizeof(address));

    (void)bip32_ckd_priv(&base, 1U, &addr);
    tap_output_key(addr.pub, xonly);
    bech32m_encode_p2tr(xonly, address, sizeof(address));
    if (strcmp(address, expected1) != 0) ok = 0;

    secure_wipe(seed, sizeof(seed));
    secure_wipe(&master, sizeof(master));
    secure_wipe(&p86, sizeof(p86));
    secure_wipe(&c86, sizeof(c86));
    secure_wipe(&a86, sizeof(a86));
    secure_wipe(&base, sizeof(base));
    secure_wipe(&addr, sizeof(addr));
    secure_wipe(xonly, sizeof(xonly));
    secure_wipe(address, sizeof(address));
    return ok;
}

static int selftest_qr(void) {
    static const char *upper_address =
        "BC1P5CYXNUXMEUWUVKWFEM96LQZSZD02N6XDCJRS20CAC6YQJJWUDPXQKEDRCR";
    airgap_qr qr;
    memset(&qr, 0, sizeof(qr));
    if (!airgap_qr_encode_alphanumeric(upper_address, &qr)) return 0;
    if (qr.module[3][3] == 0U || qr.module[3][AIRGAP_QR_SIZE - 4] == 0U ||
        qr.module[AIRGAP_QR_SIZE - 4][3] == 0U ||
        qr.module[AIRGAP_QR_SIZE - 8][8] == 0U) {
        memset(&qr, 0, sizeof(qr));
        return 0;
    }
    memset(&qr, 0, sizeof(qr));
    return 1;
}

static int run_selftests(void) {
    if (!selftest_wordlist()) {
        fprintf(stderr, "BIP39 English wordlist integrity self-test FAILED\n");
        return 0;
    }
    if (!selftest_bip39()) {
        fprintf(stderr, "BIP39 self-test FAILED\n");
        return 0;
    }
    if (!selftest_input_framing()) {
        fprintf(stderr, "Input framing/key-schedule self-test FAILED\n");
        return 0;
    }
    if (!selftest_argon2id()) {
        fprintf(stderr, "Argon2id raw self-test FAILED\n");
        return 0;
    }
    if (!selftest_bip86()) {
        fprintf(stderr, "BIP86 official-vector self-test FAILED\n");
        return 0;
    }
    if (!selftest_qr()) {
        fprintf(stderr, "QR encoder self-test FAILED\n");
        return 0;
    }
    return 1;
}

static int print_address_qr(const char *address) {
    char qr_text[128] = {0};
    airgap_qr qr;
    size_t addr_len;
    memset(&qr, 0, sizeof(qr));

    if (address == NULL) return 0;
    addr_len = strlen(address);
    if (addr_len == 0U || addr_len >= sizeof(qr_text)) {
        fprintf(stderr, "%sWarning:%s address is invalid for QR buffer.\n", YELLOW, RESET);
        return 0;
    }

    for (size_t i = 0; i < addr_len; i++) {
        unsigned char c = (unsigned char)address[i];
        qr_text[i] = (char)((c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c);
    }
    qr_text[addr_len] = '\0';

    if (!airgap_qr_encode_alphanumeric(qr_text, &qr)) {
        fprintf(stderr, "%sWarning:%s QR encoding failed; use the printed address.\n",
                YELLOW, RESET);
        secure_wipe(qr_text, sizeof(qr_text));
        secure_wipe(&qr, sizeof(qr));
        return 0;
    }

    if (!airgap_qr_print_terminal(&qr)) {
        fprintf(stderr,
            "%sWarning:%s QR not rendered (stdout not interactive or terminal too narrow).\n",
            YELLOW, RESET);
        secure_wipe(qr_text, sizeof(qr_text));
        secure_wipe(&qr, sizeof(qr));
        return 0;
    }

    secure_wipe(qr_text, sizeof(qr_text));
    secure_wipe(&qr, sizeof(qr));
    return 1;
}

/* ---------- Main ---------- */
int main(int argc, char **argv) {
    char primary_secret[256] = {0};
    char secondary_secret[256] = {0};
    recovery_context recovery = {{0},{0},{0},{0}};
    uint8_t public_context_digest[32] = {0};
    uint8_t recovery_fields_fp[8] = {0};
    uint8_t entropy[32] = {0};
    char mnemonic[512] = {0};
    uint8_t seed[64] = {0};
    ext_key master = {{0},{0},{0},0};
    ext_key p86 = {{0},{0},{0},0};
    ext_key c86 = {{0},{0},{0},0};
    ext_key a86 = {{0},{0},{0},0};
    ext_key base = {{0},{0},{0},0};
    int primary_locked = 0, secondary_locked = 0, entropy_locked = 0;
    int mnemonic_locked = 0, seed_locked = 0;
    int master_locked = 0, p86_locked = 0, c86_locked = 0;
    int a86_locked = 0, base_locked = 0;
    size_t primary_len, secondary_len;
    uint32_t wallet_num;

    (void)atexit(restore_terminal_echo);
    enable_windows_ansi();
    disable_core_dumps();

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) die("secp256k1 context creation failed");
    {
        uint8_t random_seed[32];
        if (!os_random_bytes(random_seed, sizeof(random_seed)))
            die("OS randomness unavailable for secp256k1 blinding");
        if (!secp256k1_context_randomize(ctx, random_seed)) {
            secure_wipe(random_seed, sizeof(random_seed));
            die("secp256k1 context randomization failed");
        }
        secure_wipe(random_seed, sizeof(random_seed));
    }

    if (!run_selftests()) die("cryptographic self-tests failed");

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        printf("All cryptographic self-tests passed.\n");
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--qr-test") == 0) {
        static const char *test_address =
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        int rendered;
        printf("Official BIP86 first address:\n%s\n", test_address);
        rendered = print_address_qr(test_address);
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return rendered ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc != 1) {
        fprintf(stderr, "Usage: %s [--self-test | --qr-test]\n", argv[0]);
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return EXIT_FAILURE;
    }

    primary_locked = lock_secret_memory(primary_secret, sizeof(primary_secret));
    secondary_locked = lock_secret_memory(secondary_secret, sizeof(secondary_secret));
    entropy_locked = lock_secret_memory(entropy, sizeof(entropy));
    mnemonic_locked = lock_secret_memory(mnemonic, sizeof(mnemonic));
    seed_locked = lock_secret_memory(seed, sizeof(seed));
    master_locked = lock_secret_memory(&master, sizeof(master));
    p86_locked = lock_secret_memory(&p86, sizeof(p86));
    c86_locked = lock_secret_memory(&c86, sizeof(c86));
    a86_locked = lock_secret_memory(&a86, sizeof(a86));
    base_locked = lock_secret_memory(&base, sizeof(base));
    if (!primary_locked || !secondary_locked || !entropy_locked ||
        !mnemonic_locked || !seed_locked || !master_locked || !p86_locked ||
        !c86_locked || !a86_locked || !base_locked) {
        fprintf(stderr,
            "%sWarning:%s not all small secret buffers could be memory-locked.\n",
            YELLOW, RESET);
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return EXIT_FAILURE;
    }

    if (setvbuf(stdin, NULL, _IONBF, 0) != 0) die("stdin hardening failed");

    printf("%s===============================================%s\n", RED, RESET);
    printf("A I R G A P B I P 3 9  -  B Y  -  N O R D P A X\n");
    printf("Output : 24 Words STANDARD BIP39 [ English ]\n");
    printf("%s===============================================%s\n\n", RED, RESET);
    printf("Primary and Secondary Secret require at least 12 ASCII characters.\n");
    printf("The visible recovery fields below also affect the generated wallet.\n");
    printf("They must be reproduced exactly to regenerate the mnemonic from inputs.\n\n");

    warn_if_swap_active();

    primary_len = read_confirmed_secret("Primary Secret",
                                        primary_secret, sizeof(primary_secret),
                                        PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN);
    secondary_len = read_confirmed_secret("Secondary Secret",
                                          secondary_secret, sizeof(secondary_secret),
                                          SECONDARY_SECRET_MIN_LEN, SECONDARY_SECRET_MAX_LEN);

    printf("%sBoth secret pairs confirmed.%s\n", GREEN, RESET);
    printf("Fingerprints will be shown only after the memory-hard derivation.\n\n");

    read_recovery_context(&recovery);
    build_public_context_digest(&recovery, public_context_digest);

    wallet_num = read_wallet_number();

    derive_bip39_entropy(primary_secret, primary_len,
                         secondary_secret, secondary_len,
                         public_context_digest, wallet_num, entropy,
                         recovery_fields_fp);

    print_fingerprint64("\nRecovery Fields Fingerprint", recovery_fields_fp);

    secure_wipe(primary_secret, sizeof(primary_secret));
    secure_wipe(secondary_secret, sizeof(secondary_secret));
    secure_wipe(&recovery, sizeof(recovery));
    secure_wipe(public_context_digest, sizeof(public_context_digest));
    secure_wipe(recovery_fields_fp, sizeof(recovery_fields_fp));

    bip39_from_entropy_256(entropy, mnemonic, sizeof(mnemonic));
    secure_wipe(entropy, sizeof(entropy));

    bip39_seed_no_passphrase(mnemonic, seed);
    bip32_from_seed(seed, &master);
    (void)bip32_ckd_priv(&master, 86U | HARDENED, &p86);
    (void)bip32_ckd_priv(&p86, 0U | HARDENED, &c86);
    (void)bip32_ckd_priv(&c86, 0U | HARDENED, &a86);
    (void)bip32_ckd_priv(&a86, 0U, &base);

    printf("\n%sBIP39 mnemonic (24 words):%s\n", GREEN, RESET);
    print_mnemonic_cols(mnemonic);
    printf("\n");
    printf("\n%sSECURITY NOTE:%s The generated 24 words provide full wallet access.\n\n",YELLOW, RESET);

    {
        ext_key addr = {{0},{0},{0},0};
        uint8_t xonly[32] = {0};
        char address[128] = {0};
        uint32_t actual = bip32_ckd_priv(&base, 0U, &addr);

        tap_output_key(addr.pub, xonly);
        bech32m_encode_p2tr(xonly, address, sizeof(address));

        uint8_t wallet_fp[8] = {0};

        printf("BTC Taproot BIP86 address:\n");
        printf("m/86'/0'/0'/0/%u: %s\n", actual, address);
        if (actual != 0U)
            printf("  [requested 0; BIP32 invalid-child skip occurred]");
        fputc('\n', stdout);

        derive_wallet_address_fingerprint(address, wallet_fp);
         
        (void)print_address_qr(address);

        print_fingerprint64("\nWallet Input Fingerprint", wallet_fp);
        
        secure_wipe(wallet_fp, sizeof(wallet_fp));
        secure_wipe(&addr, sizeof(addr));
        secure_wipe(xonly, sizeof(xonly));
        secure_wipe(address, sizeof(address));
    }

    

    /* Cleanup secrets. */
    secure_wipe(&recovery, sizeof(recovery));
    secure_wipe(public_context_digest, sizeof(public_context_digest));
    secure_wipe(recovery_fields_fp, sizeof(recovery_fields_fp));
    secure_wipe(seed, sizeof(seed));
    secure_wipe(mnemonic, sizeof(mnemonic));
    secure_wipe(&master, sizeof(master));
    secure_wipe(&p86, sizeof(p86));
    secure_wipe(&c86, sizeof(c86));
    secure_wipe(&a86, sizeof(a86));
    secure_wipe(&base, sizeof(base));

    if (base_locked) unlock_secret_memory(&base, sizeof(base));
    if (a86_locked) unlock_secret_memory(&a86, sizeof(a86));
    if (c86_locked) unlock_secret_memory(&c86, sizeof(c86));
    if (p86_locked) unlock_secret_memory(&p86, sizeof(p86));
    if (master_locked) unlock_secret_memory(&master, sizeof(master));
    if (seed_locked) unlock_secret_memory(seed, sizeof(seed));
    if (mnemonic_locked) unlock_secret_memory(mnemonic, sizeof(mnemonic));
    if (entropy_locked) unlock_secret_memory(entropy, sizeof(entropy));
    if (secondary_locked) unlock_secret_memory(secondary_secret, sizeof(secondary_secret));
    if (primary_locked) unlock_secret_memory(primary_secret, sizeof(primary_secret));

#ifdef _WIN32
    printf("\nPress ENTER to exit...");
    (void)getchar();
#endif

    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return EXIT_SUCCESS;
}
