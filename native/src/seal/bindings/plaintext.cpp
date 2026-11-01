// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_plaintext)
{
    class_<Plaintext>("Plaintext")
        .constructor<>()
        .constructor<std::size_t>()
        .constructor<std::size_t, std::size_t>()
        // Move factory results into JS-owned handles to preserve their pool and reserved capacity.
        .class_function(
            "withPool", optional_override([](const MemoryPoolHandle &pool) { return Plaintext(pool); }),
            return_value_policy::take_ownership())
        .class_function(
            "withCoeffCountAndPool", optional_override([](std::size_t coeff_count, const MemoryPoolHandle &pool) {
                return Plaintext(coeff_count, pool);
            }),
            return_value_policy::take_ownership())
        .class_function(
            "withCapAndCoeffCountAndPool",
            optional_override([](std::size_t capacity, std::size_t coeff_count, const MemoryPoolHandle &pool) {
                return Plaintext(capacity, coeff_count, pool);
            }),
            return_value_policy::take_ownership())
        .function("assign", optional_override([](Plaintext &self, const Plaintext &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const Plaintext &self) { return Plaintext(self); }),
            return_value_policy::take_ownership())
        .function("saveToBase64", &saveToBase64Helper<Plaintext>)
        .function("saveToArray", &saveToArrayHelper<Plaintext>)
        .function("loadFromBase64", &loadFromBase64Helper<Plaintext>)
        .function("loadFromArray", &loadFromArrayHelper<Plaintext>)
        .function("reserve", &Plaintext::reserve)
        .function("shrinkToFit", &Plaintext::shrink_to_fit)
        .function("release", &Plaintext::release)
        .function("resize", &Plaintext::resize)
        .function("setZero", optional_override([](Plaintext &self) { self.set_zero(); }))
        .function("isZero", &Plaintext::is_zero)
        .function("capacity", &Plaintext::capacity)
        .function("coeffCount", &Plaintext::coeff_count)
        .function("significantCoeffCount", &Plaintext::significant_coeff_count)
        .function("nonzeroCoeffCount", &Plaintext::nonzero_coeff_count)
        .function("toString", &Plaintext::to_string)
        .function("isNttForm", select_overload<bool() const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload<const parms_id_type &() const>(&Plaintext::parms_id))
        .function("scale", select_overload<const double &() const>(&Plaintext::scale))
        .function("setScale", optional_override([](Plaintext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Plaintext::pool);
}
