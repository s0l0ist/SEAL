// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;

namespace seal
{
    namespace bindings
    {
        std::string typedArrayName(const val &data)
        {
            return data.isNull() || data.isUndefined() ? std::string{} : data["constructor"]["name"].as<std::string>();
        }
    } // namespace bindings
} // namespace seal
