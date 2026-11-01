// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_encoders)
{
    class_<BatchEncoder>("BatchEncoder")
        .constructor<const SEALContext &>()
        .function("slotCount", &BatchEncoder::slot_count)
        .function(
            "encode", optional_override([](const BatchEncoder &self, const emscripten::val &v, Plaintext &destination) {
                const auto ctor = typedArrayName(v);
                if (ctor == "BigInt64Array")
                {
                    auto values = convertJSArrayToNumberVector<std::int64_t>(v);
                    self.encode(values, destination);
                }
                else if (ctor == "BigUint64Array")
                {
                    auto values = convertJSArrayToNumberVector<std::uint64_t>(v);
                    self.encode(values, destination);
                }
                else
                {
                    throw std::invalid_argument("expected one of BigInt64Array, BigUint64Array");
                }
            }))
        .function("decodeBigInt64", optional_override([](const BatchEncoder &self, const Plaintext &plain) {
                      std::vector<std::int64_t> dst;
                      self.decode(plain, dst);
                      return copyToTypedArray(dst.size(), dst.data());
                  }))
        .function(
            "decodeBigInt64WithPool",
            optional_override([](const BatchEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                std::vector<std::int64_t> dst;
                self.decode(plain, dst, pool);
                return copyToTypedArray(dst.size(), dst.data());
            }))

        .function("decodeBigUint64", optional_override([](const BatchEncoder &self, const Plaintext &plain) {
                      std::vector<std::uint64_t> dst;
                      self.decode(plain, dst);
                      return copyToTypedArray(dst.size(), dst.data());
                  }))
        .function(
            "decodeBigUint64WithPool",
            optional_override([](const BatchEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                std::vector<std::uint64_t> dst;
                self.decode(plain, dst, pool);
                return copyToTypedArray(dst.size(), dst.data());
            }));

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<const SEALContext &>()
        .function("slotCount", &CKKSEncoder::slot_count)
        .function(
            "encode", optional_override(
                          [](const CKKSEncoder &self, const emscripten::val &v, double scale, Plaintext &destination) {
                              auto values = vectorFromTypedArray<double>(v, "Float64Array");
                              self.encode(values, scale, destination);
                          }))
        .function(
            "encodeWithPool", optional_override([](const CKKSEncoder &self, const emscripten::val &v, double scale,
                                                   Plaintext &destination, const MemoryPoolHandle &pool) {
                auto values = vectorFromTypedArray<double>(v, "Float64Array");
                self.encode(values, scale, destination, pool);
            }))
        .function("decodeFloat64", optional_override([](const CKKSEncoder &self, const Plaintext &plain) {
                      std::vector<double> dst;
                      self.decode(plain, dst);

                      return copyToTypedArray(dst.size(), dst.data());
                  }))

        .function(
            "decodeFloat64WithPool",
            optional_override([](const CKKSEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                std::vector<double> dst;
                self.decode(plain, dst, pool);

                return copyToTypedArray(dst.size(), dst.data());
            }));
}
