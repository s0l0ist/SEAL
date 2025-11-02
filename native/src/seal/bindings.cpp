#include <cstdint>
#include <emscripten/bind.h>
#include <iomanip>
#include <stdexcept>
#include <typeinfo>
#include "base64.h"
#include "seal.h"

using namespace std;
using namespace emscripten;
using namespace seal;

template <typename T>
emscripten::val jsArrayFromVec(const std::vector<T> &vec)
{
    return val(typed_memory_view(vec.size(), vec.data()));
};

emscripten::val jsArrayModulusFromVec(const std::vector<Modulus> &vec)
{
    std::vector<uint64_t> res(vec.size());
    std::transform(vec.begin(), vec.end(), res.begin(), [](const Modulus &m) { return m.value(); });
    return val::array(res.begin(), res.end());
};

template <typename T>
std::string saveToStringHelper(const T &self, compr_mode_type mode)
{
    const size_t n = self.save_size(mode);
    std::vector<seal_byte> buf(n);
    const size_t written = self.save(buf.data(), buf.size(), mode);
    return b64encode(buf.data(), written);
}

template <typename T>
std::vector<uint8_t> saveToArrayHelper(const T &self, compr_mode_type mode)
{
    const size_t n = self.save_size(mode);
    std::vector<seal_byte> buf(n);
    const size_t written = self.save(buf.data(), buf.size(), mode);
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t *>(buf.data()), reinterpret_cast<const uint8_t *>(buf.data()) + written);
}

template <typename T>
void loadFromStringHelper(T &self, SEALContext &context, const std::string &encoded)
{
    std::string decoded = b64decode(encoded);
    self.load(context, reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
}

template <typename T>
void loadFromArrayHelper(T &self, SEALContext &context, const val &v)
{
    std::vector<uint8_t> data = convertJSArrayToNumberVector<uint8_t>(v);
    self.load(context, reinterpret_cast<const seal_byte *>(data.data()), data.size());
}

template <typename T>
void loadFromStringHelperNoContext(T &self, const std::string &encoded)
{
    std::string decoded = b64decode(encoded);
    self.load(reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
}

template <typename T>
void loadFromArrayHelperNoContext(T &self, const val &v)
{
    std::vector<uint8_t> data = convertJSArrayToNumberVector<uint8_t>(v);
    self.load(reinterpret_cast<const seal_byte *>(data.data()), data.size());
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
std::string printContext(const SEALContext &context)
{
    auto context_data = context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data->parms().scheme())
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
    oss << "|   poly_modulus_degree: " << context_data->parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    oss << "|   coeff_modulus size: ";
    oss << context_data->total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data->parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        oss << coeff_modulus[i].bit_count() << " + ";
    }
    oss << coeff_modulus.back().bit_count();
    oss << ") bits" << std::endl;

    /*
    For the 'bfv'' scheme print the plain_modulus parameter.
    */
    if (context_data->parms().scheme() == seal::scheme_type::bfv ||
        context_data->parms().scheme() == seal::scheme_type::bgv)
    {
        oss << "|   plain_modulus: " << context_data->parms().plain_modulus().value() << std::endl;
    }

    oss << "\\" << std::endl;
    return oss.str();
}

/*
 Gets the exception string from the thrown pointer
*/
std::string get_exception(intptr_t ptr)
{
    auto exception = reinterpret_cast<std::exception *>(ptr);
    return exception->what();
}

template <class F>
struct y_combinator
{
    F f; // the lambda will be stored here

    // a forwarding operator():
    template <class... Args>
    decltype(auto) operator()(Args &&...args) const
    {
        // we pass ourselves to f, then the arguments.
        // the lambda should take the first argument as `auto&& recurse` or similar.
        return f(*this, std::forward<Args>(args)...);
    }
};
// helper function that deduces the type of the lambda:
template <class F>
y_combinator<std::decay_t<F>> make_y_combinator(F &&f)
{
    return { std::forward<F>(f) };
}

EMSCRIPTEN_BINDINGS(SEAL)
{
    register_vector<Plaintext>("VectorPlaintext");
    register_vector<Ciphertext>("VectorCiphertext");
    register_vector<uint8_t>("VectorU8");
    register_vector<int32_t>("VectorI32");
    register_vector<uint32_t>("VectorU32");
    register_vector<int64_t>("VectorI64");
    register_vector<uint64_t>("VectorU64");
    register_vector<double>("VectorF64");
    register_vector<Modulus>("VectorModulus");

    emscripten::function("getException", &get_exception);

    emscripten::function("jsArrayUint8FromVec", &jsArrayFromVec<uint8_t>);
    emscripten::function("jsArrayInt32FromVec", &jsArrayFromVec<int32_t>);
    emscripten::function("jsArrayUint32FromVec", &jsArrayFromVec<uint32_t>);
    emscripten::function("jsArrayFloat64FromVec", &jsArrayFromVec<double>);
    emscripten::function("jsArrayBigInt64FromVec", &jsArrayFromVec<int64_t>);
    emscripten::function("jsArrayBigUint64FromVec", &jsArrayFromVec<uint64_t>);
    emscripten::function("jsArrayModulusFromVec", &jsArrayModulusFromVec);

    emscripten::function("vecFromArrayUint8", &convertJSArrayToNumberVector<uint8_t>);
    emscripten::function("vecFromArrayInt32", &convertJSArrayToNumberVector<int32_t>);
    emscripten::function("vecFromArrayUint32", &convertJSArrayToNumberVector<uint32_t>);
    emscripten::function("vecFromArrayFloat64", &convertJSArrayToNumberVector<double>);
    emscripten::function("vecFromArrayBigInt64", &convertJSArrayToNumberVector<int64_t>);
    emscripten::function("vecFromArrayBigUint64", &convertJSArrayToNumberVector<uint64_t>);
    emscripten::function("vecFromArrayModulus", &vecFromJSArray<Modulus>);

    class_<util::HashFunction>("UtilHashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", optional_override([](const val &v) {
                            std::vector<uint64_t> input = convertJSArrayToNumberVector<uint64_t>(v);
                            util::HashFunction::hash_block_type result;
                            util::HashFunction::hash(input.data(), input.size(), result);
                            return result;
                        }));

    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .constructor<parms_id_type &&>()
        .function("values", optional_override([](const parms_id_type &self) {
                      std::vector<uint64_t> res(self.begin(), self.end());
                      return emscripten::val::array(res.begin(), res.end());
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
        .class_function("BFVDefault", &CoeffModulus::BFVDefault)
        .class_function("CreateFromArray", optional_override([](std::size_t poly_modulus_degree, const val &v) {
                            std::vector<int> bit_sizes = convertJSArrayToNumberVector<int>(v);
                            return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
                        }));
    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<Modulus(std::size_t, int)>(&PlainModulus::Batching))
        .class_function(
            "BatchingVector",
            select_overload<std::vector<Modulus>(std::size_t, std::vector<int>)>(&PlainModulus::Batching));

    class_<Modulus>("Modulus")
        .constructor<>()
        .constructor<Modulus &&>()
        .function("isZero", &Modulus::is_zero)
        .function("isPrime", &Modulus::is_prime)
        .function("bitCount", &Modulus::bit_count)
        .function("saveToString", &saveToStringHelper<Modulus>)
        .function("saveToArray", &saveToArrayHelper<Modulus>)
        .function("loadFromString", &loadFromStringHelperNoContext<Modulus>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<Modulus>)
        .function("setValue", optional_override([](Modulus &self, uint64_t value) { self = value; }))
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
        .function("saveToString", &saveToStringHelper<EncryptionParameters>)
        .function("saveToArray", &saveToArrayHelper<EncryptionParameters>)
        .function("loadFromString", &loadFromStringHelperNoContext<EncryptionParameters>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<EncryptionParameters>);

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .function("parametersSet", &EncryptionParameterQualifiers::parameters_set)
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level);

    class_<std::shared_ptr<const SEALContext::ContextData>>("ContextData")
        .function("parms", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms();
                  }))
        .function("parmsId", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms_id();
                  }))
        .function("qualifiers", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->qualifiers();
                  }))
        // .function(
        //     "totalCoeffModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->total_coeff_modulus();
        //     }),
        //     allow_raw_pointers())
        .function(
            "totalCoeffModulusBitCount", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                return self->total_coeff_modulus_bit_count();
            }))
        // .function(
        //     "coeffDivPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->coeff_div_plain_modulus();
        //     }),
        //     allow_raw_pointers())
        // .function("baseConverter", &SEALContext::ContextData::base_converter)
        // .function("smallNttTables", &SEALContext::ContextData::small_ntt_tables)
        // .function("plainNttTables", &SEALContext::ContextData::plain_ntt_tables)
        // .function(
        //     "plainUpperHalfThreshold", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->plain_upper_half_threshold();
        //     }),
        //     allow_raw_pointers())
        // .function(
        //     "plainUpperHalfIncrement", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->plain_upper_half_increment();
        //     }),
        //     allow_raw_pointers())
        // .function(
        //     "upperHalfThreshold", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->upper_half_threshold();
        //     }),
        //     allow_raw_pointers())
        // .function(
        //     "upperHalfIncrement", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //         return self->upper_half_increment();
        //     }),
        //     allow_raw_pointers())
        // .function("coeffModPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self)
        // {
        //               return self->coeff_mod_plain_modulus();
        //           }))
        .function("prevContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->prev_context_data();
                  }))
        .function("nextContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->next_context_data();
                  }))
        .function("chainIndex", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->chain_index();
                  }));

    class_<SEALContext>("SEALContext")
        .constructor<const EncryptionParameters &, bool, sec_level_type>()
        .function("copy", optional_override([](SEALContext &self, const SEALContext &copy) { self = copy; }))
        .function("duplicate", optional_override([](const SEALContext &self) { return SEALContext(self); }))
        .function("move", optional_override([](SEALContext &self, SEALContext &&assign) { self = std::move(assign); }))
        .function("toHuman", &printContext)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("keyParmsId", &SEALContext::key_parms_id)
        .function("firstParmsId", &SEALContext::first_parms_id)
        .function("lastParmsId", &SEALContext::last_parms_id)
        .function("usingKeyswitching", &SEALContext::using_keyswitching);

    class_<Evaluator>("Evaluator")
        .constructor<const SEALContext &>()
        .function("negate", &Evaluator::negate)
        .function("add", &Evaluator::add)
        .function("addPlain", &Evaluator::add_plain)
        .function("sub", &Evaluator::sub)
        .function("subPlain", &Evaluator::sub_plain)
        .function("multiply", &Evaluator::multiply)
        .function("multiplyPlain", &Evaluator::multiply_plain)
        .function("square", &Evaluator::square)
        .function(
            "exponentiate", optional_override([](Evaluator &self, const Ciphertext &encrypted, uint32_t exponent,
                                                 const RelinKeys &relin_keys, Ciphertext &destination,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                self.exponentiate(encrypted, static_cast<uint64_t>(exponent), relin_keys, destination, pool);
            }))
        .function("relinearize", &Evaluator::relinearize)
        .function(
            "cipherModSwitchToNext", select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle) const>(
                                         &Evaluator::mod_switch_to_next))
        .function(
            "cipherModSwitchTo",
            select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to))
        .function(
            "plainModSwitchToNext",
            select_overload<void(const Plaintext &, Plaintext &) const>(&Evaluator::mod_switch_to_next))
        .function(
            "plainModSwitchTo",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &) const>(&Evaluator::mod_switch_to))
        .function("rescaleToNext", &Evaluator::rescale_to_next)
        .function("rescaleTo", &Evaluator::rescale_to)
        .function("modReduceToNext", &Evaluator::mod_reduce_to_next)
        .function("modReduceTo", &Evaluator::mod_reduce_to)
        .function(
            "plainTransformToNtt",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt))
        .function(
            "cipherTransformToNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_to_ntt))
        .function(
            "cipherTransformFromNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_from_ntt))
        .function(
            "applyGalois", optional_override([](Evaluator &self, const Ciphertext &encrypted, uint32_t g_elt,
                                                const GaloisKeys &gal_keys, Ciphertext &destination,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                self.apply_galois(encrypted, static_cast<uint64_t>(g_elt), gal_keys, destination, pool);
            }))
        .function("rotateRows", &Evaluator::rotate_rows)
        .function("rotateColumns", &Evaluator::rotate_columns)
        .function("rotateVector", &Evaluator::rotate_vector)
        .function("complexConjugate", &Evaluator::complex_conjugate)
        .function(
            "sumElements", optional_override([](Evaluator &self, const Ciphertext &encrypted,
                                                const GaloisKeys &gal_keys, scheme_type scheme, Ciphertext &destination,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                if (scheme == scheme_type::none)
                {
                    throw std::logic_error("unsupported scheme");
                }

                const std::size_t poly_deg = encrypted.poly_modulus_degree();
                if (poly_deg == 0 || (poly_deg & (poly_deg - 1)) != 0)
                {
                    throw std::out_of_range("encrypted poly_modulus_degree must be a power of 2");
                }

                Ciphertext temp = encrypted;
                int rotateSteps = poly_deg / 4;

                if (scheme == scheme_type::ckks)
                {
                    auto sum_elements = make_y_combinator([](auto &&sum_elements, Evaluator &self, Ciphertext &a,
                                                             int steps, const GaloisKeys &gal_keys,
                                                             Ciphertext &destination, MemoryPoolHandle pool) {
                        if (steps < 1)
                        {
                            destination = std::move(a);
                            return;
                        }
                        self.rotate_vector(a, steps, gal_keys, destination, pool);
                        self.add(a, destination, a);
                        return sum_elements(self, a, steps / 2, gal_keys, destination, pool);
                    });

                    sum_elements(self, temp, rotateSteps, gal_keys, destination, pool);
                    return;
                }

                if (scheme == scheme_type::bfv || scheme == scheme_type::bgv)
                {
                    auto sum_elements = make_y_combinator([](auto &&sum_elements, Evaluator &self, Ciphertext &a,
                                                             int steps, const GaloisKeys &gal_keys,
                                                             Ciphertext &destination, MemoryPoolHandle pool) {
                        if (steps < 1)
                        {
                            destination = std::move(a);
                            return;
                        }
                        self.rotate_rows(a, steps, gal_keys, destination, pool);
                        self.rotate_columns(destination, gal_keys, destination, pool);
                        self.add(a, destination, a);
                        return sum_elements(self, a, steps / 2, gal_keys, destination, pool);
                    });

                    self.rotate_columns(temp, gal_keys, destination, pool);
                    self.add(temp, destination, temp);
                    sum_elements(self, temp, rotateSteps, gal_keys, destination, pool);
                }
            }))
        .function(
            "linearTransformPlain",
            optional_override([](Evaluator &self, const Ciphertext &ct, const std::vector<Plaintext> &U_diagonals,
                                 const GaloisKeys &gal_keys) {
                const std::size_t diagSize = U_diagonals.size();

                Ciphertext ct_rot;
                self.rotate_vector(ct, -diagSize, gal_keys, ct_rot);

                Ciphertext ct_new;
                self.add(ct, ct_rot, ct_new);

                std::vector<Ciphertext> ct_result(diagSize);
                self.multiply_plain(ct_new, U_diagonals[0], ct_result[0]);

                for (std::size_t l = 1; l < diagSize; l++)
                {
                    Ciphertext temp_rot;
                    self.rotate_vector(ct_new, l, gal_keys, temp_rot);
                    if (U_diagonals[l].is_zero())
                    {
                        continue;
                    }
                    self.multiply_plain(temp_rot, U_diagonals[l], ct_result[l]);
                }

                Ciphertext ct_prime;
                self.add_many(ct_result, ct_prime);
                return ct_prime;
            }));

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("size", &KSwitchKeys::size)
        .function("saveToString", &saveToStringHelper<KSwitchKeys>)
        .function("saveToArray", &saveToArrayHelper<KSwitchKeys>)
        .function("loadFromString", &loadFromStringHelper<KSwitchKeys>)
        .function("loadFromArray", &loadFromArrayHelper<KSwitchKeys>);

    class_<RelinKeys, base<KSwitchKeys>>("RelinKeys")
        .constructor<>()
        .constructor<RelinKeys &&>()
        .function("getIndex", optional_override([](RelinKeys &self, uint32_t key_power) {
                      return self.get_index(key_power);
                  }))
        .function(
            "hasKey", optional_override([](RelinKeys &self, uint32_t key_power) { return self.has_key(key_power); }))
        // .function(
        //     "key", optional_override([](RelinKeys &self, uint32_t key_power) { return self.key(key_power); }))
        .function("copy", optional_override([](RelinKeys &self, const RelinKeys &copy) { self = copy; }))
        .function("duplicate", optional_override([](const RelinKeys &self) { return RelinKeys(self); }))
        .function("move", optional_override([](RelinKeys &self, RelinKeys &&assign) { self = std::move(assign); }));

    class_<GaloisKeys, base<KSwitchKeys>>("GaloisKeys")
        .constructor<>()
        .constructor<GaloisKeys &&>()
        .function("getIndex", optional_override([](GaloisKeys &self, uint32_t g_elt) { return self.get_index(g_elt); }))
        .function("hasKey", optional_override([](GaloisKeys &self, uint32_t g_elt) { return self.has_key(g_elt); }))
        // .function("key", optional_override([](GaloisKeys &self, uint32_t g_elt) {
        //               return self.key(static_cast<uint64_t>(g_elt));
        //           }))
        .function("copy", optional_override([](GaloisKeys &self, const GaloisKeys &copy) { self = copy; }))
        .function("duplicate", optional_override([](const GaloisKeys &self) { return GaloisKeys(self); }))
        .function("move", optional_override([](GaloisKeys &self, GaloisKeys &&assign) { self = std::move(assign); }));
    class_<Serializable<PublicKey>>("SerializablePublicKey")
        .function("saveToString", &saveToStringHelper<Serializable<PublicKey>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<PublicKey>>);
    class_<Serializable<RelinKeys>>("SerializableRelinKeys")
        .function("saveToString", &saveToStringHelper<Serializable<RelinKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<RelinKeys>>);
    class_<Serializable<GaloisKeys>>("SerializableGaloisKeys")
        .function("saveToString", &saveToStringHelper<Serializable<GaloisKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<GaloisKeys>>);
    class_<Serializable<Ciphertext>>("SerializableCiphertext")
        .function("saveToString", &saveToStringHelper<Serializable<Ciphertext>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<Ciphertext>>);

    class_<KeyGenerator>("KeyGenerator")
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, const SecretKey &>()
        .function("secretKey", &KeyGenerator::secret_key)
        .function("createPublicKey", select_overload<void(PublicKey &) const>(&KeyGenerator::create_public_key))
        .function(
            "createPublicKeySerializable",
            select_overload<Serializable<PublicKey>() const>(&KeyGenerator::create_public_key))
        .function("createRelinKeys", select_overload<void(RelinKeys &)>(&KeyGenerator::create_relin_keys))
        .function(
            "createRelinKeysSerializable", select_overload<Serializable<RelinKeys>()>(&KeyGenerator::create_relin_keys))
        .function("createGaloisKeys", optional_override([](KeyGenerator &self, const val &v, GaloisKeys &keys) {
                      const size_t length = v["length"].as<size_t>();
                      if (length == 0)
                      {
                          self.create_galois_keys(keys);
                          return;
                      }
                      std::vector<int32_t> steps = convertJSArrayToNumberVector<int32_t>(v);
                      self.create_galois_keys(steps, keys);
                  }))
        .function("createGaloisKeysSerializable", optional_override([](KeyGenerator &self, const val &v) {
                      const size_t length = v["length"].as<size_t>();
                      if (length == 0)
                      {
                          return self.create_galois_keys();
                      }
                      std::vector<int32_t> steps = convertJSArrayToNumberVector<int32_t>(v);
                      return self.create_galois_keys(steps);
                  }));
    class_<PublicKey>("PublicKey")
        .constructor<>()
        .constructor<PublicKey &&>()
        .function("copy", optional_override([](PublicKey &self, const PublicKey &copy) { self = copy; }))
        .function("duplicate", optional_override([](const PublicKey &self) { return PublicKey(self); }))
        .function("move", optional_override([](PublicKey &self, PublicKey &&assign) { self = std::move(assign); }))
        .function("saveToString", &saveToStringHelper<PublicKey>)
        .function("saveToArray", &saveToArrayHelper<PublicKey>)
        .function("loadFromString", &loadFromStringHelper<PublicKey>)
        .function("loadFromArray", &loadFromArrayHelper<PublicKey>);

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .constructor<SecretKey &&>()
        .function("copy", optional_override([](SecretKey &self, const SecretKey &copy) { self = copy; }))
        .function("duplicate", optional_override([](const SecretKey &self) { return SecretKey(self); }))
        .function("move", optional_override([](SecretKey &self, SecretKey &&assign) { self = std::move(assign); }))
        .function("saveToString", &saveToStringHelper<SecretKey>)
        .function("saveToArray", &saveToArrayHelper<SecretKey>)
        .function("loadFromString", &loadFromStringHelper<SecretKey>)
        .function("loadFromArray", &loadFromArrayHelper<SecretKey>);

    class_<Plaintext>("Plaintext")
        .constructor<MemoryPoolHandle>()
        .constructor<std::size_t, MemoryPoolHandle>()
        .constructor<std::size_t, std::size_t, MemoryPoolHandle>()
        .function("copy", optional_override([](Plaintext &self, const Plaintext &copy) { self = copy; }))
        .function("duplicate", optional_override([](const Plaintext &self) { return Plaintext(self); }))
        .function("move", optional_override([](Plaintext &self, Plaintext &&assign) { self = std::move(assign); }))
        .function("saveToString", &saveToStringHelper<Plaintext>)
        .function("saveToArray", &saveToArrayHelper<Plaintext>)
        .function("loadFromString", &loadFromStringHelper<Plaintext>)
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
        .function("toPolynomial", &Plaintext::to_string)
        .function("isNttForm", select_overload<bool() const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Plaintext::parms_id))
        .function("scale", select_overload<double &()>(&Plaintext::scale))
        .function("setScale", optional_override([](Plaintext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Plaintext::pool);

    class_<Ciphertext>("Ciphertext")
        .constructor<MemoryPoolHandle>()
        .constructor<const SEALContext &, MemoryPoolHandle>()
        .constructor<const SEALContext &, parms_id_type, MemoryPoolHandle>()
        .constructor<const SEALContext &, parms_id_type, std::size_t, MemoryPoolHandle>()
        .function("copy", optional_override([](Ciphertext &self, const Ciphertext &copy) { self = copy; }))
        .function("duplicate", optional_override([](const Ciphertext &self) { return Ciphertext(self); }))
        .function("move", optional_override([](Ciphertext &self, Ciphertext &&assign) { self = std::move(assign); }))
        .function("saveToString", &saveToStringHelper<Ciphertext>)
        .function("saveToArray", &saveToArrayHelper<Ciphertext>)
        .function("loadFromString", &loadFromStringHelper<Ciphertext>)
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
        .function("parmsId", select_overload<parms_id_type &()>(&Ciphertext::parms_id))
        .function("scale", select_overload<double &()>(&Ciphertext::scale))
        .function("correctionFactor", select_overload<double &()>(&Ciphertext::scale))
        .function("setScale", optional_override([](Ciphertext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Ciphertext::pool);

    class_<BatchEncoder>("BatchEncoder")
        .constructor<const SEALContext &>()
        .function(
            "encode",
            optional_override([](BatchEncoder &self, const val &v, Plaintext &destination, const std::string &type) {
                if (type == "INT32")
                {
                    std::vector<int32_t> temp = convertJSArrayToNumberVector<int32_t>(v);
                    std::vector<int64_t> values(temp.begin(), temp.end());
                    self.encode(values, destination);
                }
                else if (type == "UINT32")
                {
                    std::vector<uint32_t> temp = convertJSArrayToNumberVector<uint32_t>(v);
                    std::vector<uint64_t> values(temp.begin(), temp.end());
                    self.encode(values, destination);
                }
                else if (type == "INT64")
                {
                    std::vector<int64_t> values = convertJSArrayToNumberVector<int64_t>(v);
                    self.encode(values, destination);
                }
                else if (type == "UINT64")
                {
                    std::vector<uint64_t> values = convertJSArrayToNumberVector<uint64_t>(v);
                    self.encode(values, destination);
                }
            }))
        .function(
            "decodeBigInt", optional_override([](BatchEncoder &self, const Plaintext &plain, const bool &sign,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                const size_t slots = self.slot_count();
                if (sign)
                {
                    std::vector<int64_t> dst(slots);
                    self.decode(plain, dst, pool);
                    val ta = val::global("BigInt64Array").new_(slots);
                    ta.call<void>("set", typed_memory_view(slots, dst.data()));
                    return ta;
                }
                else
                {
                    std::vector<uint64_t> dst(slots);
                    self.decode(plain, dst, pool);
                    val ta = val::global("BigUint64Array").new_(slots);
                    ta.call<void>("set", typed_memory_view(slots, dst.data()));
                    return ta;
                }
            }))
        .function(
            "decodeInt32", optional_override([](BatchEncoder &self, const Plaintext &plain,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::vector<int64_t> destination(self.slot_count());
                self.decode(plain, destination, pool);
                return std::vector<int32_t>(destination.begin(), destination.end());
            }))
        .function(
            "decodeUint32", optional_override([](BatchEncoder &self, const Plaintext &plain,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::vector<uint64_t> destination(self.slot_count());
                self.decode(plain, destination, pool);
                return std::vector<uint32_t>(destination.begin(), destination.end());
            }))
        .function("slotCount", &BatchEncoder::slot_count);

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<const SEALContext &>()
        .function(
            "encode", optional_override([](CKKSEncoder &self, const val &v, double scale, Plaintext &destination,
                                           MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::vector<double> values = convertJSArrayToNumberVector<double>(v);
                self.encode(values, scale, destination, pool);
            }))
        .function(
            "decodeDouble", optional_override([](CKKSEncoder &self, const Plaintext &plain,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::vector<double> destination;
                self.decode(plain, destination, pool);
                return destination;
            }))
        .function("slotCount", &CKKSEncoder::slot_count);

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("MemoryPoolHandleGlobal", &MemoryPoolHandle::Global)
        .class_function("MemoryPoolHandleThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("MemoryPoolHandleNew", &MemoryPoolHandle::New);

    class_<MemoryManager>("MemoryManager")
        .class_function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool));

    class_<MMProf>("MMProf");

    class_<MMProfGlobal, base<MMProf>>("MMProfGlobal").function("getPool", &MMProfGlobal::get_pool);

    class_<MMProfNew, base<MMProf>>("MMProfNew").function("getPool", &MMProfNew::get_pool);

    class_<MMProfFixed, base<MMProf>>("MMProfFixed").function("getPool", &MMProfFixed::get_pool);

    class_<MMProfThreadLocal, base<MMProf>>("MMProfThreadLocal").function("getPool", &MMProfThreadLocal::get_pool);

    class_<Encryptor>("Encryptor")
        .constructor<const SEALContext &, const PublicKey &>()
        .constructor<const SEALContext &, const PublicKey &, const SecretKey &>()
        .function("setPublicKey", &Encryptor::set_public_key)
        .function("setSecretKey", &Encryptor::set_secret_key)
        .function(
            "encrypt",
            select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function(
            "encryptSerializable",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function(
            "encryptSymmetric", select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(
                                    &Encryptor::encrypt_symmetric))
        .function(
            "encryptSymmetricSerializable",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(
                &Encryptor::encrypt_symmetric))
        .function("encryptZero", select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt_zero))
        .function(
            "encryptZeroSerializable",
            select_overload<Serializable<Ciphertext>(MemoryPoolHandle) const>(&Encryptor::encrypt_zero));

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
