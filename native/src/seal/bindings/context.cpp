// Licensed under the MIT license.

#include "seal/bindings/helpers.h"
#include "seal/util/ntt.h"
#include <sstream>

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

namespace
{
    ModOperandArray copyModOperands(std::size_t size, const util::MultiplyUIntModOperand *values)
    {
        if (!values)
        {
            return ModOperandArray(val::array());
        }
        return ModOperandArray(val::array(std::vector<util::MultiplyUIntModOperand>(values, values + size)));
    }

    util::MultiplyUIntModOperand nttRootPower(const util::NTTTables &tables, std::size_t index, bool inverse)
    {
        if (index >= tables.coeff_count())
        {
            throw std::out_of_range("index");
        }
        return inverse ? tables.get_from_inv_root_powers(index) : tables.get_from_root_powers(index);
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

EMSCRIPTEN_BINDINGS(seal_context)
{
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
}
