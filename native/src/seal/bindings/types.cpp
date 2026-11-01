// Licensed under the MIT license.

#include "seal/bindings/helpers.h"
#include <algorithm>

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

namespace
{
    emscripten::val modulusValues(const std::vector<Modulus> &vec)
    {
        std::vector<std::uint64_t> res(vec.size());
        std::transform(vec.begin(), vec.end(), res.begin(), [](const Modulus &m) { return m.value(); });
        return val::array(res);
    }
} // namespace

EMSCRIPTEN_BINDINGS(seal_types)
{
    register_type<Uint64Array>("BigUint64Array");
    register_type<ModOperandArray>("MultiplyUIntModOperand[]");
    register_type<NTTTableArray>("NTTTables[]");
    register_type<PublicKeyArray>("PublicKey[]");

    register_vector<Modulus>("VectorModulus");

    value_object<util::MultiplyUIntModOperand>("MultiplyUIntModOperand")
        .field("operand", &util::MultiplyUIntModOperand::operand)
        .field("quotient", &util::MultiplyUIntModOperand::quotient);

    emscripten::function("modulusValues", &modulusValues);
    emscripten::function("modulusVectorFromArray", &vecFromJSArray<Modulus>, return_value_policy::take_ownership());

    enum_<sec_level_type>("SecLevelType")
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256);

    enum_<compr_mode_type>("ComprModeType")
        .value("none", compr_mode_type::none)
#ifdef SEAL_USE_ZLIB
        .value("zlib", compr_mode_type::zlib)
#endif
#ifdef SEAL_USE_ZSTD
        .value("zstd", compr_mode_type::zstd)
#endif
        ;

    enum_<scheme_type>("SchemeType")
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks)
        .value("bgv", scheme_type::bgv);
}
