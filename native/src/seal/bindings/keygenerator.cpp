// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_keygenerator)
{
    class_<KeyGenerator>("KeyGenerator")
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, const SecretKey &>()
        .function("secretKey", &KeyGenerator::secret_key)
        // Move newly generated keys into JS-owned handles without copying their buffers.
        .function(
            "createPublicKey", optional_override([](const KeyGenerator &self) {
                seal::PublicKey pk;
                self.create_public_key(pk);
                return pk;
            }),
            return_value_policy::take_ownership())
        .function(
            "createPublicKeySerializable",
            select_overload<Serializable<PublicKey>() const>(&KeyGenerator::create_public_key),
            return_value_policy::take_ownership())

        .function(
            "createRelinKeys", optional_override([](KeyGenerator &self) {
                seal::RelinKeys rk;
                self.create_relin_keys(rk);
                return rk;
            }),
            return_value_policy::take_ownership())

        .function(
            "createRelinKeysSerializable", select_overload<Serializable<RelinKeys>()>(&KeyGenerator::create_relin_keys),
            return_value_policy::take_ownership())
        .function(
            "createGaloisKeys", optional_override([](KeyGenerator &self) {
                seal::GaloisKeys gk;
                self.create_galois_keys(gk);
                return gk;
            }),
            return_value_policy::take_ownership())
        .function(
            "createGaloisKeysWithSteps", optional_override([](KeyGenerator &self, const val &v) {
                auto steps = vectorFromTypedArray<std::int32_t>(v, "Int32Array");
                seal::GaloisKeys gk;
                self.create_galois_keys(steps, gk);
                return gk;
            }),
            return_value_policy::take_ownership())
        .function(
            "createGaloisKeysSerializable",
            select_overload<Serializable<GaloisKeys>()>(&KeyGenerator::create_galois_keys),
            return_value_policy::take_ownership())
        .function(
            "createGaloisKeysSerializableWithSteps", optional_override([](KeyGenerator &self, const val &v) {
                auto steps = vectorFromTypedArray<std::int32_t>(v, "Int32Array");
                return self.create_galois_keys(steps);
            }),
            return_value_policy::take_ownership());
}
