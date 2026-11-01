// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_utilhashfunction)
{
    class_<util::HashFunction>("UtilHashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", optional_override([](const val &v) {
                            auto input = vectorFromTypedArray<std::uint64_t>(v, "BigUint64Array");
                            util::HashFunction::hash_block_type result;
                            util::HashFunction::hash(input.data(), input.size(), result);

                            return copyToTypedArray(result.size(), result.data());
                        }));
}
