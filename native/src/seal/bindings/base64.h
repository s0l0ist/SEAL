// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <string>

namespace seal
{
    namespace bindings
    {
        std::string encodeBase64(const void *data, std::size_t size);
        std::string decodeBase64(const std::string &encoded);
    } // namespace bindings
} // namespace seal
