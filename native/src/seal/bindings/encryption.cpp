// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_encryption)
{
    class_<Encryptor>("Encryptor")
        .constructor<const SEALContext &, const PublicKey &>()
        .constructor<const SEALContext &, const PublicKey &, const SecretKey &>()
        .function("setPublicKey", &Encryptor::set_public_key)
        .function("setSecretKey", &Encryptor::set_secret_key)
        .function("encrypt", optional_override([](const Encryptor &self, const Plaintext &plain, Ciphertext &cipher) {
                      self.encrypt(plain, cipher);
                  }))
        .function(
            "encryptWithPool",
            select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function(
            "encryptSerializable",
            optional_override([](const Encryptor &self, const Plaintext &plain) { return self.encrypt(plain); }),
            return_value_policy::take_ownership())
        .function(
            "encryptSerializableWithPool",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(&Encryptor::encrypt),
            return_value_policy::take_ownership())

        .function(
            "encryptSymmetric", optional_override([](const Encryptor &self, const Plaintext &plain,
                                                     Ciphertext &cipher) { self.encrypt_symmetric(plain, cipher); }))
        .function(
            "encryptSymmetricWithPool", select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(
                                            &Encryptor::encrypt_symmetric))

        .function(
            "encryptSymmetricSerializable", optional_override([](const Encryptor &self, const Plaintext &plain) {
                return self.encrypt_symmetric(plain);
            }),
            return_value_policy::take_ownership())
        .function(
            "encryptSymmetricSerializableWithPool",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(
                &Encryptor::encrypt_symmetric),
            return_value_policy::take_ownership())

        .function("encryptZero", optional_override([](const Encryptor &self, Ciphertext &cipher) {
                      self.encrypt_zero(cipher);
                  }))
        .function(
            "encryptZeroWithPool",
            select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt_zero))
        .function(
            "encryptZeroSerializable", optional_override([](const Encryptor &self) { return self.encrypt_zero(); }),
            return_value_policy::take_ownership())
        .function(
            "encryptZeroSerializableWithPool",
            select_overload<Serializable<Ciphertext>(MemoryPoolHandle) const>(&Encryptor::encrypt_zero),
            return_value_policy::take_ownership());

    class_<Decryptor>("Decryptor")
        .constructor<const SEALContext &, const SecretKey &>()
        .function("decrypt", &Decryptor::decrypt)
        .function("invariantNoiseBudget", &Decryptor::invariant_noise_budget);
}
