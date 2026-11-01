// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_encryptionparameters)
{
    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .constructor<const parms_id_type &>()
        .function("values", optional_override([](const parms_id_type &self) {
                      return copyToTypedArray(self.size(), self.data());
                  }));

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
}
