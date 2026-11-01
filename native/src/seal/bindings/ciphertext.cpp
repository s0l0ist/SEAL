// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_ciphertext)
{
    class_<Ciphertext>("Ciphertext")
        .constructor<>()
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, parms_id_type>()
        .constructor<const SEALContext &, parms_id_type, std::size_t>()
        .class_function(
            "withPool", optional_override([](MemoryPoolHandle pool) { return Ciphertext(pool); }),
            return_value_policy::take_ownership())
        .class_function(
            "withContextAndPool",
            optional_override([](const SEALContext &ctx, MemoryPoolHandle pool) { return Ciphertext(ctx, pool); }),
            return_value_policy::take_ownership())
        .class_function(
            "withContextAndParmsIdTypeAndPool",
            optional_override([](const SEALContext &ctx, parms_id_type parms, MemoryPoolHandle pool) {
                return Ciphertext(ctx, parms, pool);
            }),
            return_value_policy::take_ownership())
        .class_function(
            "withContextAndParmsIdTypeAndCapacityAndPool",
            optional_override([](const SEALContext &ctx, parms_id_type parms, std::size_t size_capacity,
                                 MemoryPoolHandle pool) { return Ciphertext(ctx, parms, size_capacity, pool); }),
            return_value_policy::take_ownership())

        .function("assign", optional_override([](Ciphertext &self, const Ciphertext &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const Ciphertext &self) { return Ciphertext(self); }),
            return_value_policy::take_ownership())
        .function("saveToBase64", &saveToBase64Helper<Ciphertext>)
        .function("saveToArray", &saveToArrayHelper<Ciphertext>)
        .function("loadFromBase64", &loadFromBase64Helper<Ciphertext>)
        .function("loadFromArray", &loadFromArrayHelper<Ciphertext>)
        .function("reserve", select_overload<void(const SEALContext &, std::size_t)>(&Ciphertext::reserve))
        .function("resize", select_overload<void(std::size_t)>(&Ciphertext::resize))
        .function("release", &Ciphertext::release)
        .function("coeffModulusSize", &Ciphertext::coeff_modulus_size)
        .function("polyModulusDegree", &Ciphertext::poly_modulus_degree)
        .function("size", &Ciphertext::size)
        .function("sizeCapacity", &Ciphertext::size_capacity)
        .function("isTransparent", &Ciphertext::is_transparent)
        .function("isNttForm", select_overload<bool() const>(&Ciphertext::is_ntt_form))
        .function("parmsId", select_overload<const parms_id_type &() const>(&Ciphertext::parms_id))
        .function("scale", select_overload<const double &() const>(&Ciphertext::scale))
        .function("correctionFactor", select_overload<const std::uint64_t &() const>(&Ciphertext::correction_factor))
        .function("setScale", optional_override([](Ciphertext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Ciphertext::pool);

    class_<Serializable<Ciphertext>>("SerializableCiphertext")
        .function("saveToBase64", &saveToBase64Helper<Serializable<Ciphertext>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<Ciphertext>>);
}
