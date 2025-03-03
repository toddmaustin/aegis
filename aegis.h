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
#include <type_traits>

namespace aegis {

// --- Global Ephemeral Key and Key Schedule ---
//
// A global ephemeral 128-bit key is generated on first use along with its AES-128 key schedule.
// We store only the encryption key schedule (ephemeral_enc_keys) and use it (in reverse order)
// for decryption.
static __m128i ephemeral_enc_keys[11];
static __m128i ephemeral_key;
static bool ephemeral_key_initialized = false;

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

static void init_ephemeral_key() {
    if (!ephemeral_key_initialized) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis;
        uint32_t randomParts[4] = { dis(gen), dis(gen), dis(gen), dis(gen) };
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

        ephemeral_key_initialized = true;
    }
}

// AES-128 encryption: iterate forward over ephemeral_enc_keys.
static inline __m128i AES_128_Enc_Block(__m128i block) {
    init_ephemeral_key();
    block = _mm_xor_si128(block, ephemeral_enc_keys[0]);
    for (int i = 1; i < 10; i++) {
        block = _mm_aesenc_si128(block, ephemeral_enc_keys[i]);
    }
    block = _mm_aesenclast_si128(block, ephemeral_enc_keys[10]);
    return block;
}

// AES-128 decryption: iterate in reverse order, applying inverse MixColumns on intermediate keys.
static inline __m128i AES_128_Dec_Block(__m128i block) {
    init_ephemeral_key();
    block = _mm_xor_si128(block, ephemeral_enc_keys[10]);
    for (int i = 9; i >= 1; i--) {
        block = _mm_aesdec_si128(block, _mm_aesimc_si128(ephemeral_enc_keys[i]));
    }
    block = _mm_aesdeclast_si128(block, ephemeral_enc_keys[0]);
    return block;
}

// --- EncInt Class ---
//
// EncInt supports all standard integral types (up to 64 bits). For types smaller than 64 bits,
// PlainState embeds a union to pad the value to 64 bits. The plaintext state (padded value, salt, hash)
// is packed into a 128-bit block and encrypted using AES-128. Every operation (construction, assignment,
// cast, arithmetic, etc.) generates a new random salt.
template<typename T>
class EncInt {
    static_assert(std::is_integral<T>::value, "EncInt requires an integral type");
    static_assert(sizeof(T) <= sizeof(uint64_t), "EncInt supports types up to 64 bits");
private:
    // PlainState embeds a union directly.
    struct PlainState {
        union {
            uint64_t pad;
            T val;
        } value;
        uint32_t salt;
        uint32_t hash;
    };

    // The encrypted state stored as a 128-bit block.
    __m128i encrypted_state;

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

    // Encrypt the PlainState into encrypted_state.
    void encState(const PlainState &ps) {
        __m128i plain = _mm_set_epi32(ps.hash, ps.salt,
                                        static_cast<int>(ps.value.pad >> 32),
                                        static_cast<int>(ps.value.pad & 0xffffffff));
        encrypted_state = AES_128_Enc_Block(plain);
    }

    // Decrypt the encrypted_state and return the PlainState.
    PlainState decState() const {
        __m128i plain = AES_128_Dec_Block(encrypted_state);
        PlainState ps;
        uint32_t low = _mm_extract_epi32(plain, 0);
        uint32_t high = _mm_extract_epi32(plain, 1);
        ps.hash = _mm_extract_epi32(plain, 2);
        ps.salt = _mm_extract_epi32(plain, 3);
        ps.value.pad = (static_cast<uint64_t>(high) << 32) | low;
        return ps;
    }

    // Update the state with a new value: generate new salt and compute new hash.
    void updState(T newVal) {
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = newVal;
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
    }

public:
    // Constructors.
    EncInt() {
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = 0;
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
    }
    EncInt(T v) {
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = v;
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
    }
    // Deterministic constructor.
    EncInt(T v, uint32_t s) {
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = v;
        ps.salt = s;
        ps.hash = computeHash(ps.value.pad, s);
        encState(ps);
    }

    // Copy constructor: decrypt then re-encrypt with new random salt.
    EncInt(const EncInt &other) {
        PlainState ps = other.decState();
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
    }
    EncInt &operator=(const EncInt &other) {
        if (this != &other) {
            PlainState ps = other.decState();
            ps.salt = static_cast<uint32_t>(rand());
            ps.hash = computeHash(ps.value.pad, ps.salt);
            encState(ps);
        }
        return *this;
    }

    // Templated conversion constructor.
    template<typename U, typename = typename std::enable_if<std::is_integral<U>::value &&
                                                               std::is_convertible<U, T>::value>::type>
    EncInt(const EncInt<U> &other) {
        uint64_t v = other.getValue();
        PlainState ps;
        ps.value.pad = 0;
        ps.value.val = static_cast<T>(v);
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
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
        ps.salt = static_cast<uint32_t>(rand());
        ps.hash = computeHash(ps.value.pad, ps.salt);
        encState(ps);
        return *this;
    }

    // Getters.
    T getValue() {
        PlainState ps = decState();
        return ps.value.val;
    }
    uint32_t getSalt() {
        return decState().salt;
    }
    uint32_t getHash() {
        return decState().hash;
    }

    // Arithmetic operators.
    EncInt operator+(const EncInt &other) const {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        return EncInt(ps1.value.val + ps2.value.val);
    }
    EncInt operator-(const EncInt &other) const {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        return EncInt(ps1.value.val - ps2.value.val);
    }
    EncInt operator*(const EncInt &other) const {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        return EncInt(ps1.value.val * ps2.value.val);
    }
    EncInt operator/(const EncInt &other) const {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        return EncInt(ps1.value.val / ps2.value.val);
    }
    EncInt operator%(const EncInt &other) const {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        return EncInt(ps1.value.val % ps2.value.val);
    }

    // Compound assignment operator example.
    EncInt &operator+=(const EncInt &other) {
        PlainState ps1 = decState();
        PlainState ps2 = other.decState();
        updState(ps1.value.val + ps2.value.val);
        return *this;
    }

    // Explicit conversion operator to underlying type.
    explicit operator T() {
        return getValue();
    }

    // For demonstration: friend operator<<.
    friend std::ostream &operator<<(std::ostream &os, const EncInt &ei) {
        PlainState ps = ei.decState();
        os << ps.value.val;
        return os;
    }
};

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

} // namespace aegis

#endif // AEGIS_H

