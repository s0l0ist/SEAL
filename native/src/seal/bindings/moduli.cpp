// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_moduli)
{
    class_<Modulus>("Modulus")
        .constructor<std::uint64_t>()
        .function("isZero", &Modulus::is_zero)
        .function("isPrime", &Modulus::is_prime)
        .function("bitCount", &Modulus::bit_count)
        .function("saveToBase64", &saveToBase64Helper<Modulus>)
        .function("saveToArray", &saveToArrayHelper<Modulus>)
        .function("loadFromBase64", &loadFromBase64HelperNoContext<Modulus>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<Modulus>)
        .function("setValue", optional_override([](Modulus &self, std::uint64_t value) { self = value; }))
        .function("value", &Modulus::value);

    class_<CoeffModulus>("CoeffModulus")
        .class_function("MaxBitCount", &CoeffModulus::MaxBitCount)
        .class_function("BFVDefault", &CoeffModulus::BFVDefault, return_value_policy::take_ownership())
        .class_function(
            "Create", optional_override([](std::size_t poly_modulus_degree, const val &v) {
                auto bit_sizes = vectorFromTypedArray<std::int32_t>(v, "Int32Array");
                return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
            }),
            return_value_policy::take_ownership());

    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<Modulus(std::size_t, std::int32_t)>(&PlainModulus::Batching))
        .class_function(
            "BatchingVector", optional_override([](std::size_t poly_modulus_degree, const emscripten::val &v) {
                auto bit_sizes = vectorFromTypedArray<std::int32_t>(v, "Int32Array");
                return PlainModulus::Batching(poly_modulus_degree, bit_sizes);
            }),
            return_value_policy::take_ownership());
}
