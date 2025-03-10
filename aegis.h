#ifndef AEGIS_H
#define AEGIS_H

#include <cstdint>
#include <cassert>
#include <iostream>
#include <random>
#include <cstring>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>
#include <immintrin.h>  // Required for _rdseed32_step and _rdseed64_step
#include <type_traits>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void
print_m128i(const char *varname, __m128i value)
{
    uint8_t bytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes), value);

    printf("%s: ", varname);
    for (int i = 0; i < 16; i++) {
        printf("%02x", bytes[i]);  // Print as hexadecimal
    }
    printf("\n");
}

namespace aegis {

// --- Global Ephemeral Key and Key Schedule ---
//
// A global ephemeral 128-bit key is generated on first use along with its AES-128 key schedule.
// We store only the encryption key schedule (ephemeral_enc_keys) and use it (in reverse order)
// for decryption.
static __m128i ephemeral_enc_keys[11];
static __m128i ephemeral_key;
static bool ephemeral_key_initialized = false;

// Global register variables for keys 0-9.
// These are bound to XMM registers xmm0 through xmm9 and will persist throughout execution.
volatile register __m128i g_temp  asm("xmm4");
volatile register __m128i g_key0  asm("xmm5");
volatile register __m128i g_key1  asm("xmm6");
volatile register __m128i g_key2  asm("xmm7");
volatile register __m128i g_key3  asm("xmm8");
volatile register __m128i g_key4  asm("xmm9");
volatile register __m128i g_key5  asm("xmm10");
volatile register __m128i g_key6  asm("xmm11");
volatile register __m128i g_key7  asm("xmm12");
volatile register __m128i g_key8  asm("xmm13");
volatile register __m128i g_key9  asm("xmm14");
volatile register __m128i g_key10 asm("xmm15");

// Macro for AES-128 key expansion step. RC must be an immediate constant.
#define AES128_KEY_EXPANSION_STEP(KEY, RC) ({                      \
    __m128i _key = (KEY);                                          \
    __m128i _temp = _mm_aeskeygenassist_si128(_key, (RC));         \
    _temp = _mm_shuffle_epi32(_temp, _MM_SHUFFLE(3,3,3,3));          \
    _key = _mm_xor_si128(_key, _mm_slli_si128(_key, 4));             \
    _key = _mm_xor_si128(_key, _mm_slli_si128(_key, 4));             \
    _key = _mm_xor_si128(_key, _mm_slli_si128(_key, 4));             \
    _mm_xor_si128(_key, _temp);                                      \
})

#define _my_rdrand64_step(x) ({ unsigned char err; asm volatile(".byte 0x48; .byte 0x0f; .byte 0xc7; .byte 0xf0; setc %1":"=a"(*x), "=qm"(err)); err; })


static void
init_ephemeral_key(void)
{
    if (!ephemeral_key_initialized) {
        int success;
        long long unsigned rdrand_value;
        while (!(success =  _my_rdrand64_step(&rdrand_value)));
        // printf("rdrand_value = 0x%lx\n", (uint64_t)rdrand_value);
        std::mt19937 gen((uint64_t)rdrand_value);
        std::uniform_int_distribution<uint32_t> dis;
        uint32_t randomParts[4] = { dis(gen), dis(gen), dis(gen), dis(gen) };
        // printf("randomParts[] = { %08x, %08x, %08x, %08x }\n", randomParts[3], randomParts[2], randomParts[1], randomParts[0]);
        ephemeral_key = _mm_set_epi32(randomParts[3], randomParts[2], randomParts[1], randomParts[0]);

        ephemeral_enc_keys[0] = ephemeral_key;
        ephemeral_enc_keys[1] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[0], 0x01);
        ephemeral_enc_keys[2] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[1], 0x02);
        ephemeral_enc_keys[3] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[2], 0x04);
        ephemeral_enc_keys[4] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[3], 0x08);
        ephemeral_enc_keys[5] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[4], 0x10);
        ephemeral_enc_keys[6] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[5], 0x20);
        ephemeral_enc_keys[7] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[6], 0x40);
        ephemeral_enc_keys[8] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[7], 0x80);
        ephemeral_enc_keys[9] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[8], 0x1B);
        ephemeral_enc_keys[10] = AES128_KEY_EXPANSION_STEP(ephemeral_enc_keys[9], 0x36);

        // Bind the first 10 keys to XMM registers.
        g_key0 = ephemeral_enc_keys[0];
        g_key1 = ephemeral_enc_keys[1];
        g_key2 = ephemeral_enc_keys[2];
        g_key3 = ephemeral_enc_keys[3];
        g_key4 = ephemeral_enc_keys[4];
        g_key5 = ephemeral_enc_keys[5];
        g_key6 = ephemeral_enc_keys[6];
        g_key7 = ephemeral_enc_keys[7];
        g_key8 = ephemeral_enc_keys[8];
        g_key9 = ephemeral_enc_keys[9];
        g_key10 = ephemeral_enc_keys[10];

        // xmm14 is the incrementing salt value
        __m128i salt_value = _mm_set_epi32(0, 0, dis(gen), 0);
        g_key9 = salt_value;

        // xmm13 is the incrementor value
        __m128i salt_increment = _mm_set_epi32(0, 0, 1, 0);
        g_key8 = salt_increment;

#if 0
        for (unsigned i=0; i <= 10; i++)
          print_m128i("key[]", ephemeral_enc_keys[i]);
        ephemeral_key_initialized = true;
#endif
    }
}

// AES-128 encryption: iterate forward over ephemeral_enc_keys.
register uint64_t value_arg asm("ebx");
static /*inline*/ __m128i
AES_128_Enc_Block(/* value_arg */)
{
  // build the plaintext 128-bit word
  register __m128i block asm("xmm0")
     = _mm_set_epi32(static_cast<int>(value_arg >> 32),
                     static_cast<int>(value_arg & 0xffffffff),
                     0, /* hash */42);

  // mix in the salt value
  __asm__ volatile (
     "paddd   %xmm13, %xmm14    \n\t" // salt = salt + 1
     "paddd   %xmm14, %xmm0     \n\t" // mix in the salt
  );

  __asm__ volatile (
      "pxor   %%xmm5, %0        \n\t"  // block ^= g_key0
      "aesenc %%xmm6, %0        \n\t"  // round 1: use g_key1
      "aesenc %%xmm7, %0        \n\t"  // round 2: use g_key2
      "aesenc %%xmm8, %0        \n\t"  // round 3: use g_key3
      "aesenc %%xmm9, %0        \n\t"  // round 4: use g_key4
      "aesenc %%xmm10, %0       \n\t"  // round 5: use g_key5
      "aesenc %%xmm11, %0       \n\t"  // round 6: use g_key6
      // "aesenc %%xmm12, %0       \n\t"  // round 7: use g_key7
      // "aesenc %%xmm13, %0       \n\t"  // round 8: use g_key8
      // "aesenc %%xmm14, %0       \n\t"  // round 9: use g_key9
      "aesenclast %%xmm15, %0   \n\t"  // final round with ephemeral_enc_keys[10]
      : "+x" (block)
      : 
  );
  return block;
}

// AES-128 decryption: iterate in reverse order, applying inverse MixColumns on intermediate keys.
static /*inline*/ /* __m128i */ void
AES_128_Dec_Block(__m128i block)
{
    __asm__ volatile (
        "pxor   %%xmm15, %0       \n\t"  // block ^= ephemeral_enc_keys[10]
        // "aesimc %%xmm14, %%xmm4   \n\t"
        // "aesdec %%xmm4, %0        \n\t"  // round 1: using inverse of g_key9
        // "aesimc %%xmm13, %%xmm4   \n\t"
        // "aesdec %%xmm4, %0        \n\t"  // round 2: using inverse of g_key8
        // "aesimc %%xmm12, %%xmm4   \n\t"
        // "aesdec %%xmm4, %0        \n\t"  // round 3: using inverse of g_key7
        "aesimc %%xmm11, %%xmm4   \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 4: using inverse of g_key6
        "aesimc %%xmm10, %%xmm4   \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 5: using inverse of g_key5
        "aesimc %%xmm9, %%xmm4    \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 6: using inverse of g_key4
        "aesimc %%xmm8, %%xmm4    \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 7: using inverse of g_key3
        "aesimc %%xmm7, %%xmm4    \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 8: using inverse of g_key2
        "aesimc %%xmm6, %%xmm4    \n\t"
        "aesdec %%xmm4, %0        \n\t"  // round 9: using inverse of g_key1
        "aesdeclast %%xmm5, %0    \n\t"  // final round with g_key0
        // outputs
        : "+x" (block)
        // inputs
        : 
        // clobbers
        : "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
    );

    // check the authentication "cookie"
    __asm__ volatile (
       "movd %xmm0, %ebx     \n\t" // Move lowest 32-bit lane into EBX
       "cmpq $0x2a, %rbx     \n\t" // Compare with 42
       "jne __authfail       \n\t" // Jump if equal
   );

    uint32_t low = _mm_extract_epi32(block, 2);
    uint32_t high = _mm_extract_epi32(block, 3);
    value_arg = (static_cast<uint64_t>(high) << 32) | low;
}

// --- EncInt Class ---
//
// EncInt supports all standard integral types (up to 64 bits). For types smaller than 64 bits,
// PlainState embeds a union to pad the value to 64 bits. The plaintext state (padded value, salt, hash)
// is packed into a 128-bit block and encrypted using AES-128. Every operation (construction, assignment,
// cast, arithmetic, etc.) generates a new random salt.
class EncInt {
public: /* FIXME: */
    // The encrypted state stored as a 128-bit block.
    __m128i encrypted_state;

private:
    // PlainState embeds a union directly.
    struct PlainState {
        uint64_t value;
        uint32_t salt;
        uint32_t hash;
    };

#if 0
    // Compute a 32-bit hash from the padded value and salt.
    static uint32_t computeHash(uint64_t paddedVal, uint32_t salt) {
        uint64_t combined = paddedVal ^ salt;
        combined ^= combined >> 33;
        combined *= 0xff51afd7ed558ccdULL;
        combined ^= combined >> 33;
        combined *= 0xc4ceb9fe1a85ec53ULL;
        combined ^= combined >> 33;
        return static_cast<uint32_t>(combined);
    }
#endif

#if 0
    // Decrypt the encrypted_state and return the PlainState.
    PlainState decState() const {
        __m128i plain = AES_128_Dec_Block(encrypted_state);
        PlainState ps;
        uint32_t low = _mm_extract_epi32(plain, 0);
        uint32_t high = _mm_extract_epi32(plain, 1);
        // ps.hash = _mm_extract_epi32(plain, 2);
        // ps.salt = _mm_extract_epi32(plain, 3);
        ps.value = (static_cast<uint64_t>(high) << 32) | low;
        return ps;
    }
#endif

    // Update the state with a new value: generate new salt and compute new hash.
    void updState(uint64_t newVal) {
        // ps.salt = static_cast<uint32_t>(rand());
        // ps.hash = computeHash(ps.value.pad, ps.salt);
        value_arg = newVal;
        encrypted_state = AES_128_Enc_Block();
    }

public:
    // Constructors.
    EncInt() {
        value_arg = 0;
        encrypted_state = AES_128_Enc_Block();
    }
    EncInt(uint64_t v) {
        value_arg = v;
        encrypted_state = AES_128_Enc_Block();
    }
    EncInt(__m128i c) {
        encrypted_state = c;
    }
#if 0
    // Deterministic constructor.
    EncInt(T v, uint32_t s) {
        PlainState ps;
        ps.value = v;
        encrypted_state = AES_128_Enc_Block(ps.value);
    }
#endif

    // Copy constructor: decrypt then re-encrypt with new random salt.
    EncInt(const EncInt &other) {
        AES_128_Dec_Block(other.encrypted_state);
        /* value_arg passes through */
        encrypted_state = AES_128_Enc_Block();
    }
    EncInt &operator=(const EncInt &other) {
        if (this != &other) {
            AES_128_Dec_Block(other.encrypted_state);
            /* value_arg passes through */
            encrypted_state = AES_128_Enc_Block();
        }
        return *this;
    }

#if 0
    // Templated conversion constructor.
    template<typename U, typename = typename std::enable_if<std::is_integral<U>::value &&
                                                               std::is_convertible<U, T>::value>::type>
    EncInt(const EncInt<U> &other) {
        uint64_t v = other.getValue();
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = static_cast<T>(v);
        // ps.salt = static_cast<uint32_t>(rand());
        // ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
    }

    // Templated conversion assignment operator.
    template<typename U, typename = typename std::enable_if<std::is_integral<U>::value &&
                                                               std::is_convertible<U, T>::value>::type>
    EncInt &operator=(const EncInt<U> &other) {
        uint64_t v = other.getValue();
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = static_cast<T>(v);
        // ps.salt = static_cast<uint32_t>(rand());
        // ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
        return *this;
    }
#endif

    // Getters.
    uint64_t getValue() {
        AES_128_Dec_Block(encrypted_state);
        return value_arg;
    }
#if 0
    uint32_t getSalt() {
        return decState().salt;
    }
    uint32_t getHash() {
        return decState().hash;
    }
#endif

    // Arithmetic operators.
    EncInt operator+(const EncInt &other) const {
        
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 + op2;
        __m128i encrypted_state = AES_128_Enc_Block();
        return EncInt(encrypted_state);
    }
    EncInt operator-(const EncInt &other) const {
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 - op2;
        __m128i encrypted_state = AES_128_Enc_Block();
        return EncInt(encrypted_state);
    }
    EncInt operator*(const EncInt &other) const {
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 * op2;
        __m128i encrypted_state = AES_128_Enc_Block();
        return EncInt(encrypted_state);
    }
    EncInt operator/(const EncInt &other) const {
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 / op2;
        __m128i encrypted_state = AES_128_Enc_Block();
        return EncInt(encrypted_state);
    }
    EncInt operator%(const EncInt &other) const {
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 % op2;
        __m128i encrypted_state = AES_128_Enc_Block();
        return EncInt(encrypted_state);
    }

    // Compound assignment operator example.
    EncInt &operator+=(const EncInt &other) {
        AES_128_Dec_Block(encrypted_state);
        uint64_t op1 = value_arg;
        AES_128_Dec_Block(other.encrypted_state);
        uint64_t op2 = value_arg;
        value_arg = op1 + op2;
        encrypted_state = AES_128_Enc_Block();
        return *this;
    }

    // Explicit conversion operator to underlying type.
    explicit operator uint64_t() {
        return getValue();
    }

#if 0
    // For demonstration: friend operator<<.
    friend std::ostream &operator<<(std::ostream &os, const EncInt &ei) {
        PlainState ps = ei.decState();
        os << ps.value;
        return os;
    }
#endif
};

#if 0
// Convenience alias template.
template<typename T>
using EncInt_t = EncInt<T>;

// Base type definitions (lower-case naming style).
using enc_int8_t   = EncInt_t<int8_t>;
using enc_uint8_t  = EncInt_t<uint8_t>;
using enc_int16_t  = EncInt_t<int16_t>;
using enc_uint16_t = EncInt_t<uint16_t>;
using enc_int32_t  = EncInt_t<int32_t>;
using enc_uint32_t = EncInt_t<uint32_t>;
using enc_int64_t  = EncInt_t<int64_t>;
using enc_uint64_t = EncInt_t<uint64_t>;
#endif

} // namespace aegis

// Static function with constructor attribute
static void __attribute__((constructor)) load_time_init()
{
    // std::cout << "Initialization routine running..." << std::endl;
    // call crypto library initialization function
    aegis::init_ephemeral_key();
}

extern "C" __attribute__((naked)) void __authfail() {
  printf("Authentication failure...\n");
  return;
}

#endif // AEGIS_H

