#include "seal/util/ntt.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <emscripten/bind.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "base64.h"
#include "seal.h"

using namespace emscripten;
using namespace seal;

namespace
{
    EMSCRIPTEN_DECLARE_VAL_TYPE(Uint64Array);
    EMSCRIPTEN_DECLARE_VAL_TYPE(ModOperandArray);
    EMSCRIPTEN_DECLARE_VAL_TYPE(NTTTableArray);
    EMSCRIPTEN_DECLARE_VAL_TYPE(PublicKeyArray);

    // SEAL owns its active profile exclusively; JS handles share ownership of the selected profile.
    class SharedMMProf : public MMProf
    {
    public:
        explicit SharedMMProf(std::shared_ptr<MMProf> profile) : profile_(std::move(profile))
        {}

        MemoryPoolHandle get_pool(mm_prof_opt_t prof_opt) override
        {
            return profile_->get_pool(prof_opt);
        }

        const std::shared_ptr<MMProf> &profile() const noexcept
        {
            return profile_;
        }

    private:
        std::shared_ptr<MMProf> profile_;
    };

    std::shared_ptr<MMProf> switchProfile(const std::shared_ptr<MMProf> &profile)
    {
        if (!profile)
        {
            throw std::invalid_argument("mm_prof cannot be null");
        }

        auto previous = MemoryManager::SwitchProfile(std::make_unique<SharedMMProf>(profile));
        if (auto shared = dynamic_cast<SharedMMProf *>(previous.get()))
        {
            return shared->profile();
        }
        return std::shared_ptr<MMProf>(std::move(previous));
    }

    template <typename T>
    val copyToTypedArray(std::size_t size, const T *data)
    {
        // Copy into a JS-owned buffer before the C++ storage is released or Wasm memory grows.
        val view(typed_memory_view(size, data));
        return view["constructor"].new_(view);
    }

    std::string typedArrayName(const val &data)
    {
        return data.isNull() || data.isUndefined() ? std::string{} : data["constructor"]["name"].as<std::string>();
    }

    template <typename T>
    std::vector<T> vectorFromTypedArray(const val &data, const char *expected_type)
    {
        if (typedArrayName(data) != expected_type)
        {
            throw std::invalid_argument(std::string("expected ") + expected_type);
        }
        return convertJSArrayToNumberVector<T>(data);
    }

    const SEALContext::ContextData &checkedContextData(const std::shared_ptr<const SEALContext::ContextData> &data)
    {
        if (!data)
        {
            throw std::invalid_argument("context data is not available");
        }
        return *data;
    }

    Uint64Array copyContextArray(const SEALContext::ContextData &data, const std::uint64_t *values)
    {
        return Uint64Array(copyToTypedArray(values ? data.parms().coeff_modulus().size() : 0, values));
    }

    ModOperandArray copyModOperands(std::size_t size, const util::MultiplyUIntModOperand *values)
    {
        if (!values)
        {
            return ModOperandArray(val::array());
        }
        return ModOperandArray(val::array(std::vector<util::MultiplyUIntModOperand>(values, values + size)));
    }

    NTTTableArray shareNTTTables(
        const std::shared_ptr<const SEALContext::ContextData> &owner, const util::NTTTables *tables, std::size_t size)
    {
        std::vector<std::shared_ptr<const util::NTTTables>> result;
        if (tables)
        {
            result.reserve(size);
            for (std::size_t i = 0; i < size; i++)
            {
                // Each table keeps its context alive without copying the precomputed data.
                result.emplace_back(owner, tables + i);
            }
        }
        return NTTTableArray(val::array(result));
    }

    util::MultiplyUIntModOperand nttRootPower(const util::NTTTables &tables, std::size_t index, bool inverse)
    {
        if (index >= tables.coeff_count())
        {
            throw std::out_of_range("index");
        }
        return inverse ? tables.get_from_inv_root_powers(index) : tables.get_from_root_powers(index);
    }

    emscripten::val jsArrayFromVecModulus(const std::vector<Modulus> &vec)
    {
        std::vector<std::uint64_t> res(vec.size());
        std::transform(vec.begin(), vec.end(), res.begin(), [](const Modulus &m) { return m.value(); });
        return val::array(res);
    }

    template <typename T>
    std::string saveToBase64Helper(const T &self, compr_mode_type mode)
    {
        const std::size_t n = self.save_size(mode);
        std::vector<seal_byte> buf(n);
        const std::size_t written = self.save(buf.data(), buf.size(), mode);
        return b64encode(buf.data(), written);
    }

    template <typename T>
    emscripten::val saveToArrayHelper(const T &self, compr_mode_type mode)
    {
        const std::size_t n = self.save_size(mode);
        std::vector<std::uint8_t> buf(n);
        const std::size_t written = self.save(reinterpret_cast<seal_byte *>(buf.data()), buf.size(), mode);
        return copyToTypedArray(written, buf.data());
    }

    template <typename T>
    void loadFromBase64Helper(T &self, const SEALContext &context, const std::string &encoded)
    {
        std::string decoded = b64decode(encoded);
        self.load(context, reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
    }

    template <typename T>
    void loadFromArrayHelper(T &self, const SEALContext &context, const emscripten::val &data)
    {
        auto buf = vectorFromTypedArray<std::uint8_t>(data, "Uint8Array");
        self.load(context, reinterpret_cast<const seal_byte *>(buf.data()), buf.size());
    }

    template <typename T>
    void loadFromBase64HelperNoContext(T &self, const std::string &encoded)
    {
        std::string decoded = b64decode(encoded);
        self.load(reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
    }

    template <typename T>
    void loadFromArrayHelperNoContext(T &self, const emscripten::val &data)
    {
        auto buf = vectorFromTypedArray<std::uint8_t>(data, "Uint8Array");
        self.load(reinterpret_cast<const seal_byte *>(buf.data()), buf.size());
    }

    std::string printContext(const SEALContext &context)
    {
        if (!context.parameters_set())
        {
            throw std::invalid_argument("encryption parameters are not set");
        }
        auto context_data = context.key_context_data();
        const auto &parms = context_data->parms();

        /*
        Which scheme are we using?
        */
        const char *scheme_name;
        switch (parms.scheme())
        {
        case seal::scheme_type::bfv:
            scheme_name = "bfv";
            break;
        case seal::scheme_type::ckks:
            scheme_name = "ckks";
            break;
        case seal::scheme_type::bgv:
            scheme_name = "bgv";
            break;
        default:
            throw std::invalid_argument("unsupported scheme");
        }

        std::ostringstream oss;

        oss << "/" << std::endl;
        oss << "| Encryption parameters :" << std::endl;
        oss << "|   scheme: " << scheme_name << std::endl;
        oss << "|   poly_modulus_degree: " << parms.poly_modulus_degree() << std::endl;

        /*
        Print the size of the true (product) coefficient modulus.
        */
        oss << "|   coeff_modulus size: ";
        oss << context_data->total_coeff_modulus_bit_count() << " (";
        const auto &coeff_modulus = parms.coeff_modulus();
        for (std::size_t i = 0; i < coeff_modulus.size(); i++)
        {
            if (i)
            {
                oss << " + ";
            }
            oss << coeff_modulus[i].bit_count();
        }
        oss << ") bits" << std::endl;

        /*
        For BFV and BGV, print the plain modulus.
        */
        if (parms.scheme() == scheme_type::bfv || parms.scheme() == scheme_type::bgv)
        {
            oss << "|   plain_modulus: " << parms.plain_modulus().value() << std::endl;
        }

        oss << "\\" << std::endl;
        return oss.str();
    }

} // namespace

EMSCRIPTEN_BINDINGS(SEAL)
{
    register_type<Uint64Array>("BigUint64Array");
    register_type<ModOperandArray>("MultiplyUIntModOperand[]");
    register_type<NTTTableArray>("NTTTables[]");
    register_type<PublicKeyArray>("PublicKey[]");

    register_vector<Modulus>("VectorModulus");

    value_object<util::MultiplyUIntModOperand>("MultiplyUIntModOperand")
        .field("operand", &util::MultiplyUIntModOperand::operand)
        .field("quotient", &util::MultiplyUIntModOperand::quotient);

    class_<std::shared_ptr<const util::NTTTables>>("NTTTables")
        .function("getRoot", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return self->get_root();
                  }))
        .function("getFromRootPowers", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return copyModOperands(self->coeff_count(), self->get_from_root_powers());
                  }))
        .function(
            "getFromRootPowers", optional_override([](const std::shared_ptr<const util::NTTTables> &self,
                                                      std::size_t index) { return nttRootPower(*self, index, false); }))
        .function("getFromInvRootPowers", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return copyModOperands(self->coeff_count(), self->get_from_inv_root_powers());
                  }))
        .function(
            "getFromInvRootPowers",
            optional_override([](const std::shared_ptr<const util::NTTTables> &self, std::size_t index) {
                return nttRootPower(*self, index, true);
            }))
        .function("invDegreeModulo", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return self->inv_degree_modulo();
                  }))
        .function("modulus", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return self->modulus();
                  }))
        .function("coeffCountPower", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return self->coeff_count_power();
                  }))
        .function("coeffCount", optional_override([](const std::shared_ptr<const util::NTTTables> &self) {
                      return self->coeff_count();
                  }));

    emscripten::function("jsArrayFromVecModulus", &jsArrayFromVecModulus);
    emscripten::function("vecFromArrayModulus", &vecFromJSArray<Modulus>, return_value_policy::take_ownership());

    class_<util::HashFunction>("UtilHashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", optional_override([](const val &v) {
                            auto input = vectorFromTypedArray<std::uint64_t>(v, "BigUint64Array");
                            util::HashFunction::hash_block_type result;
                            util::HashFunction::hash(input.data(), input.size(), result);

                            return copyToTypedArray(result.size(), result.data());
                        }));

    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .constructor<const parms_id_type &>()
        .function("values", optional_override([](const parms_id_type &self) {
                      return copyToTypedArray(self.size(), self.data());
                  }));

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

    class_<EncryptionParameters>("EncryptionParameters")
        .constructor<scheme_type>()
        .function("setPolyModulusDegree", &EncryptionParameters::set_poly_modulus_degree)
        .function("setCoeffModulus", &EncryptionParameters::set_coeff_modulus)
        .function("setPlainModulus", select_overload<void(const Modulus &)>(&EncryptionParameters::set_plain_modulus))
        .function("scheme", &EncryptionParameters::scheme)
        .function("polyModulusDegree", &EncryptionParameters::poly_modulus_degree)
        .function("coeffModulus", &EncryptionParameters::coeff_modulus)
        .function("plainModulus", &EncryptionParameters::plain_modulus)
        .function("parmsId", &EncryptionParameters::parms_id)
        .function("saveToBase64", &saveToBase64Helper<EncryptionParameters>)
        .function("saveToArray", &saveToArrayHelper<EncryptionParameters>)
        .function("loadFromBase64", &loadFromBase64HelperNoContext<EncryptionParameters>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<EncryptionParameters>);

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .function("parametersSet", &EncryptionParameterQualifiers::parameters_set)
        .function("parameterErrorName", optional_override([](const EncryptionParameterQualifiers &self) {
                      return std::string(self.parameter_error_name());
                  }))
        .function("parameterErrorMessage", optional_override([](const EncryptionParameterQualifiers &self) {
                      return std::string(self.parameter_error_message());
                  }))
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level);

    class_<std::shared_ptr<const SEALContext::ContextData>>("ContextData")
        .function(
            "parms", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                return checkedContextData(self).parms();
            }),
            return_value_policy::take_ownership())
        .function("parmsId", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return checkedContextData(self).parms_id();
                  }))
        .function("qualifiers", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return checkedContextData(self).qualifiers();
                  }))
        .function(
            "totalCoeffModulus", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                const auto &data = checkedContextData(self);
                return copyContextArray(data, data.total_coeff_modulus());
            }))
        .function(
            "totalCoeffModulusBitCount",
            optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                return checkedContextData(self).total_coeff_modulus_bit_count();
            }))
        .function(
            "coeffDivPlainModulus", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                const auto &data = checkedContextData(self);
                return copyModOperands(data.parms().coeff_modulus().size(), data.coeff_div_plain_modulus());
            }))
        .function("smallNttTables", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      const auto &data = checkedContextData(self);
                      return shareNTTTables(self, data.small_ntt_tables(), data.parms().coeff_modulus().size());
                  }))
        .function("plainNttTables", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return shareNTTTables(self, checkedContextData(self).plain_ntt_tables(), 1);
                  }))
        .function(
            "plainUpperHalfThreshold",
            optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                return checkedContextData(self).plain_upper_half_threshold();
            }))
        .function(
            "plainUpperHalfIncrement",
            optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                const auto &data = checkedContextData(self);
                return copyContextArray(data, data.plain_upper_half_increment());
            }))
        .function(
            "upperHalfThreshold", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                const auto &data = checkedContextData(self);
                return copyContextArray(data, data.upper_half_threshold());
            }))
        .function(
            "upperHalfIncrement", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                const auto &data = checkedContextData(self);
                return copyContextArray(data, data.upper_half_increment());
            }))
        .function(
            "coeffModulusModPlainModulus",
            optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                return checkedContextData(self).coeff_modulus_mod_plain_modulus();
            }))
        .function("prevContextData", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return checkedContextData(self).prev_context_data();
                  }))
        .function("nextContextData", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return checkedContextData(self).next_context_data();
                  }))
        .function("chainIndex", optional_override([](const std::shared_ptr<const SEALContext::ContextData> &self) {
                      return checkedContextData(self).chain_index();
                  }));

    class_<SEALContext>("SEALContext")
        .constructor<const EncryptionParameters &, bool, sec_level_type>()
        .function("assign", optional_override([](SEALContext &self, const SEALContext &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const SEALContext &self) { return SEALContext(self); }),
            return_value_policy::take_ownership())
        .function("toHuman", &printContext)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("parameterErrorName", optional_override([](const SEALContext &self) {
                      return std::string(self.parameter_error_name());
                  }))
        .function("parameterErrorMessage", optional_override([](const SEALContext &self) {
                      return std::string(self.parameter_error_message());
                  }))
        .function("keyParmsId", &SEALContext::key_parms_id)
        .function("firstParmsId", &SEALContext::first_parms_id)
        .function("lastParmsId", &SEALContext::last_parms_id)
        .function("usingKeyswitching", &SEALContext::using_keyswitching);

    class_<Evaluator>("Evaluator")
        .constructor<const SEALContext &>()
        // Negate
        .function("negate", &Evaluator::negate)
        .function("negateInplace", &Evaluator::negate_inplace)
        // Add
        .function("add", &Evaluator::add)
        .function("addInplace", &Evaluator::add_inplace)
        .function(
            "addPlain",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.add_plain(encrypted, plain, destination); }))
        .function("addPlainWithPool", &Evaluator::add_plain)
        .function(
            "addPlainInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.add_plain_inplace(encrypted, plain);
            }))
        .function("addPlainInplaceWithPool", &Evaluator::add_plain_inplace)
        // Sub
        .function("sub", &Evaluator::sub)
        .function("subInplace", &Evaluator::sub_inplace)
        .function(
            "subPlain",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.sub_plain(encrypted, plain, destination); }))
        .function("subPlainWithPool", &Evaluator::sub_plain)
        .function(
            "subPlainInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.sub_plain_inplace(encrypted, plain);
            }))
        .function("subPlainInplaceWithPool", &Evaluator::sub_plain_inplace)
        // Mul
        .function(
            "multiply",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted1, const Ciphertext &encrypted2,
                                 Ciphertext &destination) { self.multiply(encrypted1, encrypted2, destination); }))
        .function("multiplyWithPool", &Evaluator::multiply)
        .function(
            "multiplyInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted1, const Ciphertext &encrypted2) {
                self.multiply_inplace(encrypted1, encrypted2);
            }))
        .function("multiplyInplaceWithPool", &Evaluator::multiply_inplace)
        .function(
            "multiplyPlain",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.multiply_plain(encrypted, plain, destination); }))
        .function("multiplyPlainWithPool", &Evaluator::multiply_plain)
        .function(
            "multiplyPlainInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.multiply_plain_inplace(encrypted, plain);
            }))
        .function("multiplyPlainInplaceWithPool", &Evaluator::multiply_plain_inplace)
        // Square
        .function(
            "square", optional_override([](const Evaluator &self, const Ciphertext &encrypted,
                                           Ciphertext &destination) { self.square(encrypted, destination); }))
        .function("squareWithPool", &Evaluator::square)
        .function("squareInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted) {
                      self.square_inplace(encrypted);
                  }))
        .function("squareInplaceWithPool", &Evaluator::square_inplace)
        // Exponentiate
        .function(
            "exponentiate",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, std::uint64_t exponent,
                                 const RelinKeys &relin_keys, Ciphertext &destination) {
                self.exponentiate(encrypted, exponent, relin_keys, destination);
            }))
        .function("exponentiateWithPool", &Evaluator::exponentiate)
        .function(
            "exponentiateInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted,
                                                        std::uint64_t exponent, const RelinKeys &relin_keys) {
                self.exponentiate_inplace(encrypted, exponent, relin_keys);
            }))
        .function("exponentiateInplaceWithPool", &Evaluator::exponentiate_inplace)
        // Relinearize
        .function(
            "relinearize",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, const RelinKeys &relin_keys,
                                 Ciphertext &destination) { self.relinearize(encrypted, relin_keys, destination); }))
        .function("relinearizeWithPool", &Evaluator::relinearize)
        .function(
            "relinearizeInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const RelinKeys &relin_keys) {
                self.relinearize_inplace(encrypted, relin_keys);
            }))
        .function("relinearizeInplaceWithPool", &Evaluator::relinearize_inplace)
        // Cipher mod
        .function(
            "cipherModSwitchToNext",
            optional_override([](const Evaluator &self, const Ciphertext &cipher, Ciphertext &destination) {
                self.mod_switch_to_next(cipher, destination);
            }))
        .function(
            "cipherModSwitchToNextWithPool",
            select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to_next))
        .function("cipherModSwitchToNextInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted) {
                      self.mod_switch_to_next_inplace(encrypted);
                  }))
        .function(
            "cipherModSwitchToNextInplaceWithPool",
            select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Evaluator::mod_switch_to_next_inplace))
        .function(
            "cipherModSwitchTo",
            optional_override([](const Evaluator &self, const Ciphertext &cipher, parms_id_type parms_id,
                                 Ciphertext &destination) { self.mod_switch_to(cipher, parms_id, destination); }))
        .function(
            "cipherModSwitchToWithPool",
            select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to))
        .function(
            "cipherModSwitchToInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.mod_switch_to_inplace(encrypted, parms_id);
            }))
        .function(
            "cipherModSwitchToInplaceWithPool",
            select_overload<void(Ciphertext &, parms_id_type, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to_inplace))
        // Plain mod
        .function(
            "plainModSwitchToNext",
            select_overload<void(const Plaintext &, Plaintext &) const>(&Evaluator::mod_switch_to_next))
        .function(
            "plainModSwitchToNextInplace",
            select_overload<void(Plaintext &) const>(&Evaluator::mod_switch_to_next_inplace))
        .function(
            "plainModSwitchTo",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &) const>(&Evaluator::mod_switch_to))
        .function(
            "plainModSwitchToInplace",
            select_overload<void(Plaintext &, parms_id_type) const>(&Evaluator::mod_switch_to_inplace))

        // Rescale
        .function(
            "rescaleToNext",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, Ciphertext &destination) {
                self.rescale_to_next(encrypted, destination);
            }))
        .function("rescaleToNextWithPool", &Evaluator::rescale_to_next)
        .function("rescaleToNextInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted) {
                      self.rescale_to_next_inplace(encrypted);
                  }))
        .function("rescaleToNextInplaceWithPool", &Evaluator::rescale_to_next_inplace)
        .function(
            "rescaleTo",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, parms_id_type parms_id,
                                 Ciphertext &destination) { self.rescale_to(encrypted, parms_id, destination); }))
        .function("rescaleToWithPool", &Evaluator::rescale_to)
        .function(
            "rescaleToInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.rescale_to_inplace(encrypted, parms_id);
            }))
        .function("rescaleToInplaceWithPool", &Evaluator::rescale_to_inplace)
        // Mod reduce
        .function(
            "modReduceToNext",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, Ciphertext &destination) {
                self.mod_reduce_to_next(encrypted, destination);
            }))
        .function("modReduceToNextWithPool", &Evaluator::mod_reduce_to_next)

        .function("modReduceToNextInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted) {
                      self.mod_reduce_to_next_inplace(encrypted);
                  }))
        .function("modReduceToNextInplaceWithPool", &Evaluator::mod_reduce_to_next_inplace)
        .function(
            "modReduceTo",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, parms_id_type parms_id,
                                 Ciphertext &destination) { self.mod_reduce_to(encrypted, parms_id, destination); }))
        .function("modReduceToWithPool", &Evaluator::mod_reduce_to)
        .function(
            "modReduceToInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.mod_reduce_to_inplace(encrypted, parms_id);
            }))
        .function("modReduceToInplaceWithPool", &Evaluator::mod_reduce_to_inplace)
        // Plain to ntt
        .function(
            "plainTransformToNtt",
            optional_override([](const Evaluator &self, const Plaintext &plain, parms_id_type parms_id,
                                 Plaintext &destination) { self.transform_to_ntt(plain, parms_id, destination); }))
        .function(
            "plainTransformToNttWithPool",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt))
        .function(
            "plainTransformToNttInplace",
            optional_override([](const Evaluator &self, Plaintext &plain, parms_id_type parms_id) {
                self.transform_to_ntt_inplace(plain, parms_id);
            }))
        .function(
            "plainTransformToNttInplaceWithPool",
            select_overload<void(Plaintext &, parms_id_type, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt_inplace))
        // Cipher to ntt
        .function(
            "cipherTransformToNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_to_ntt))
        .function(
            "cipherTransformToNttInplace",
            select_overload<void(Ciphertext &) const>(&Evaluator::transform_to_ntt_inplace))
        .function(
            "cipherTransformFromNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_from_ntt))
        .function(
            "cipherTransformFromNttInplace",
            select_overload<void(Ciphertext &) const>(&Evaluator::transform_from_ntt_inplace))
        // Apply Galois
        .function(
            "applyGalois", optional_override([](const Evaluator &self, const Ciphertext &encrypted, std::uint32_t g_elt,
                                                const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.apply_galois(encrypted, g_elt, gal_keys, destination);
            }))
        .function("applyGaloisWithPool", &Evaluator::apply_galois)
        .function(
            "applyGaloisInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted,
                                                       std::uint32_t g_elt, const GaloisKeys &gal_keys) {
                self.apply_galois_inplace(encrypted, g_elt, gal_keys);
            }))
        .function("applyGaloisInplaceWithPool", &Evaluator::apply_galois_inplace)
        // Rotate rows
        .function(
            "rotateRows", optional_override([](const Evaluator &self, const Ciphertext &encrypted, std::int32_t steps,
                                               const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.rotate_rows(encrypted, steps, gal_keys, destination);
            }))
        .function(
            "rotateRowsWithPool",
            select_overload<void(const Ciphertext &, std::int32_t, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)
                                const>(&Evaluator::rotate_rows))
        .function(
            "rotateRowsInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, std::int32_t steps,
                                 const GaloisKeys &gal_keys) { self.rotate_rows_inplace(encrypted, steps, gal_keys); }))
        .function("rotateRowsInplaceWithPool", &Evaluator::rotate_rows_inplace)
        // Rotate columns
        .function(
            "rotateColumns",
            optional_override([](const Evaluator &self, const Ciphertext &encrypted, const GaloisKeys &gal_keys,
                                 Ciphertext &destination) { self.rotate_columns(encrypted, gal_keys, destination); }))
        .function("rotateColumnsWithPool", &Evaluator::rotate_columns)
        .function(
            "rotateColumnsInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const GaloisKeys &gal_keys) {
                self.rotate_columns_inplace(encrypted, gal_keys);
            }))
        .function("rotateColumnsInplaceWithPool", &Evaluator::rotate_columns_inplace)
        // Rotate vec
        .function(
            "rotateVector", optional_override([](const Evaluator &self, const Ciphertext &encrypted, std::int32_t steps,
                                                 const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.rotate_vector(encrypted, steps, gal_keys, destination);
            }))
        .function(
            "rotateVectorWithPool",
            select_overload<void(const Ciphertext &, std::int32_t, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)
                                const>(&Evaluator::rotate_vector))
        .function(
            "rotateVectorInplace", optional_override([](const Evaluator &self, Ciphertext &encrypted,
                                                        std::int32_t steps, const GaloisKeys &gal_keys) {
                self.rotate_vector_inplace(encrypted, steps, gal_keys);
            }))
        .function("rotateVectorInplaceWithPool", &Evaluator::rotate_vector_inplace)
        // Complex conjugate
        .function(
            "complexConjugate", optional_override([](const Evaluator &self, const Ciphertext &encrypted,
                                                     const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.complex_conjugate(encrypted, gal_keys, destination);
            }))
        .function("complexConjugateWithPool", &Evaluator::complex_conjugate)
        .function(
            "complexConjugateInplace",
            optional_override([](const Evaluator &self, Ciphertext &encrypted, const GaloisKeys &gal_keys) {
                self.complex_conjugate_inplace(encrypted, gal_keys);
            }))
        .function("complexConjugateInplaceWithPool", &Evaluator::complex_conjugate_inplace);

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("size", &KSwitchKeys::size)
        .function("saveToBase64", &saveToBase64Helper<KSwitchKeys>)
        .function("saveToArray", &saveToArrayHelper<KSwitchKeys>)
        .function("loadFromBase64", &loadFromBase64Helper<KSwitchKeys>)
        .function("loadFromArray", &loadFromArrayHelper<KSwitchKeys>);

    class_<RelinKeys, base<KSwitchKeys>>("RelinKeys")
        .constructor<>()
        .function("getIndex", optional_override([](const RelinKeys &, std::size_t key_power) {
                      return RelinKeys::get_index(key_power);
                  }))
        .function("hasKey", &RelinKeys::has_key)
        .function("key", optional_override([](const RelinKeys &self, std::size_t key_power) {
                      return PublicKeyArray(val::array(self.key(key_power)));
                  }))
        .function("assign", optional_override([](RelinKeys &self, const RelinKeys &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const RelinKeys &self) { return RelinKeys(self); }),
            return_value_policy::take_ownership());

    class_<GaloisKeys, base<KSwitchKeys>>("GaloisKeys")
        .constructor<>()
        .function("getIndex", optional_override([](const GaloisKeys &, std::uint32_t g_elt) {
                      return GaloisKeys::get_index(g_elt);
                  }))
        .function("hasKey", &GaloisKeys::has_key)
        .function("key", optional_override([](const GaloisKeys &self, std::uint32_t g_elt) {
                      return PublicKeyArray(val::array(self.key(g_elt)));
                  }))
        .function("assign", optional_override([](GaloisKeys &self, const GaloisKeys &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const GaloisKeys &self) { return GaloisKeys(self); }),
            return_value_policy::take_ownership());
    class_<Serializable<PublicKey>>("SerializablePublicKey")
        .function("saveToBase64", &saveToBase64Helper<Serializable<PublicKey>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<PublicKey>>);
    class_<Serializable<RelinKeys>>("SerializableRelinKeys")
        .function("saveToBase64", &saveToBase64Helper<Serializable<RelinKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<RelinKeys>>);
    class_<Serializable<GaloisKeys>>("SerializableGaloisKeys")
        .function("saveToBase64", &saveToBase64Helper<Serializable<GaloisKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<GaloisKeys>>);
    class_<Serializable<Ciphertext>>("SerializableCiphertext")
        .function("saveToBase64", &saveToBase64Helper<Serializable<Ciphertext>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<Ciphertext>>);

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
    class_<PublicKey>("PublicKey")
        .constructor<>()
        .function("assign", optional_override([](PublicKey &self, const PublicKey &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const PublicKey &self) { return PublicKey(self); }),
            return_value_policy::take_ownership())
        .function("saveToBase64", &saveToBase64Helper<PublicKey>)
        .function("saveToArray", &saveToArrayHelper<PublicKey>)
        .function("loadFromBase64", &loadFromBase64Helper<PublicKey>)
        .function("loadFromArray", &loadFromArrayHelper<PublicKey>);

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .function("assign", optional_override([](SecretKey &self, const SecretKey &copy) { self = copy; }))
        .function(
            "copy", optional_override([](const SecretKey &self) { return SecretKey(self); }),
            return_value_policy::take_ownership())
        .function("saveToBase64", &saveToBase64Helper<SecretKey>)
        .function("saveToArray", &saveToArrayHelper<SecretKey>)
        .function("loadFromBase64", &loadFromBase64Helper<SecretKey>)
        .function("loadFromArray", &loadFromArrayHelper<SecretKey>);

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

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("Global", &MemoryPoolHandle::Global)
        .class_function("ThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("New", &MemoryPoolHandle::New)
        .function(
            "isInitialized", optional_override([](const MemoryPoolHandle &self) { return static_cast<bool>(self); }))
        .function("poolCount", &MemoryPoolHandle::pool_count)
        .function("allocByteCount", &MemoryPoolHandle::alloc_byte_count)
        .function("useCount", &MemoryPoolHandle::use_count);

    class_<MemoryManager>("MemoryManager")
        .class_function("GetPool", select_overload<MemoryPoolHandle()>(&MemoryManager::GetPool))
        .class_function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool))
        .class_function("SwitchProfile", &switchProfile, nonnull<ret_val>());

    class_<MMProf>("MMProf")
        .smart_ptr<std::shared_ptr<MMProf>>("shared_ptr<MMProf>")
        .function("getPool", &MMProf::get_pool);

    class_<MMProfGlobal, base<MMProf>>("MMProfGlobal")
        .smart_ptr_constructor("shared_ptr<MMProfGlobal>", &std::make_shared<MMProfGlobal>);

    class_<MMProfNew, base<MMProf>>("MMProfNew")
        .smart_ptr_constructor("shared_ptr<MMProfNew>", &std::make_shared<MMProfNew>);

    class_<MMProfFixed, base<MMProf>>("MMProfFixed")
        .smart_ptr_constructor("shared_ptr<MMProfFixed>", optional_override([](MemoryPoolHandle pool) {
                                   return std::make_shared<MMProfFixed>(std::move(pool));
                               }));

    class_<MMProfThreadLocal, base<MMProf>>("MMProfThreadLocal")
        .smart_ptr_constructor("shared_ptr<MMProfThreadLocal>", &std::make_shared<MMProfThreadLocal>);

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

    enum_<scheme_type>("SchemeType")
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks)
        .value("bgv", scheme_type::bgv);
}
