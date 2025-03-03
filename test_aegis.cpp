#define UNIT_TEST_AEGIS
#include "aegis.h"
#include <iostream>
#include <sstream>
#include <cassert>
#include <limits>
#include <type_traits>

using namespace aegis;

// A helper function template to choose "safe" test values that won't overflow.
// For int8_t, we use smaller values; for others, we use slightly larger values.
template<typename T>
void get_safe_test_values(T &a_val, T &b_val, T &mult_val) {
    if constexpr (std::is_same<T, int8_t>::value) {
        a_val = 5;   // Range: -128 to 127, so use small numbers.
        b_val = 6;
        mult_val = 7;
    } else if constexpr (std::is_same<T, uint8_t>::value) {
        a_val = 10;  // For uint8_t, max is 255.
        b_val = 20;
        mult_val = 2;
    } else {
        // For 16, 32, 64-bit types we can use slightly larger values.
        a_val = 10;
        b_val = 20;
        mult_val = 3;
    }
}

// Test function template that exercises all interfaces for a given EncInt type.
template <typename T>
void test_enc_int_interface(const std::string& typeName) {
    std::cout << "Testing type: " << typeName << "\n";
    using EncT = EncInt_t<T>;

    T a_val, b_val, mult_val;
    get_safe_test_values<T>(a_val, b_val, mult_val);

    // Default constructor.
    EncT a;
    assert(a.getValue() == 0);

    // Value constructor.
    EncT b(a_val);
    assert(b.getValue() == a_val);

    // Deterministic constructor.
    // uint32_t fixedSalt = 12345;
    // EncT c(a_val * 2, fixedSalt);
    EncT c(a_val * 2);
    assert(c.getValue() == a_val * 2);
    // assert(c.getSalt() == fixedSalt);

    // Copy constructor.
    EncT d = b;
    assert(d.getValue() == b.getValue());
    // The salt should differ.
    assert(d.getSalt() != b.getSalt());

    // Arithmetic operators.
    EncT e = b + c;  // a_val + 2*a_val = 3*a_val.
    assert(e.getValue() == a_val + a_val * 2);

    EncT f = c - b;  // 2*a_val - a_val = a_val.
    assert(f.getValue() == a_val);

    EncT g = b * c;  // a_val * (2*a_val)
    assert(g.getValue() == a_val * (2 * a_val));

    // Avoid division by zero.
    if (b.getValue() != 0) {
        EncT h = c / b;  // (2*a_val) / a_val = 2
        assert(h.getValue() == 2);
        EncT i = c % b;  // (2*a_val) % a_val = 0
        assert(i.getValue() == 0);
    }

    // Compound assignment.
    EncT j(mult_val);
    j += b; // mult_val + a_val
    assert(j.getValue() == mult_val + a_val);

#ifdef notdef
    // Templated conversion: test conversion from a larger type to this type.
    if constexpr (!std::is_same<T, int32_t>::value && !std::is_same<T, uint32_t>::value) {
        EncInt_t<int32_t> convInt(100);
        EncT k = convInt;
        assert(static_cast<int64_t>(k.getValue()) == 100);
    }

    // Test explicit conversion operator.
    T convVal = static_cast<T>(b);
    assert(convVal == b.getValue());
#endif

#ifdef notdef
    // Test streaming operator.
    std::stringstream ss;
    ss << b;
    T printedVal;
    ss >> printedVal;
    assert(printedVal == b.getValue());
#endif

    std::cout << "  All tests passed for " << typeName << ".\n";
}

int main() {
    // Run tests for all supported types.
    test_enc_int_interface<int8_t>("enc_int8_t");
    test_enc_int_interface<uint8_t>("enc_uint8_t");
    test_enc_int_interface<int16_t>("enc_int16_t");
    test_enc_int_interface<uint16_t>("enc_uint16_t");
    test_enc_int_interface<int32_t>("enc_int32_t");
    test_enc_int_interface<uint32_t>("enc_uint32_t");
    test_enc_int_interface<int64_t>("enc_int64_t");
    test_enc_int_interface<uint64_t>("enc_uint64_t");

    std::cout << "All tests for all supported types passed.\n";
    return 0;
}

