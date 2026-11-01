// Licensed under the MIT license.
// Scalar block processing influenced by simdutf (MIT):
// https://github.com/simdutf/simdutf/blob/master/include/simdutf/scalar/base64.h

#include "seal/bindings/base64.h"
#include <cstdint>
#include <stdexcept>

namespace
{
    constexpr std::size_t batch_groups = 4;
}

namespace seal
{
    namespace bindings
    {
        std::string encodeBase64(const void *data, std::size_t size)
        {
            static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            if (!data && size)
            {
                throw std::invalid_argument("base64 data cannot be null");
            }
            const std::size_t groups = size / 3 + (size % 3 != 0);
            if (groups > std::string{}.max_size() / 4)
            {
                throw std::length_error("base64 input is too large");
            }
            std::string result(groups * 4, '=');
            auto *output = &result[0];
            const auto *input = static_cast<const unsigned char *>(data);
            const auto encode_block = [&] {
                const std::uint32_t bits = (std::uint32_t(input[0]) << 16) | (std::uint32_t(input[1]) << 8) | input[2];
                output[0] = alphabet[bits >> 18];
                output[1] = alphabet[(bits >> 12) & 63];
                output[2] = alphabet[(bits >> 6) & 63];
                output[3] = alphabet[bits & 63];
                input += 3;
                output += 4;
            };
            std::size_t remaining = size;
            while (remaining >= 3 * batch_groups)
            {
                for (unsigned block = 0; block < batch_groups; ++block)
                {
                    encode_block();
                }
                remaining -= 3 * batch_groups;
            }
            while (remaining >= 3)
            {
                encode_block();
                remaining -= 3;
            }
            if (remaining)
            {
                const std::uint32_t bits =
                    (std::uint32_t(input[0]) << 16) | (remaining == 2 ? std::uint32_t(input[1]) << 8 : 0);
                output[0] = alphabet[bits >> 18];
                output[1] = alphabet[(bits >> 12) & 63];
                if (remaining == 2)
                {
                    output[2] = alphabet[(bits >> 6) & 63];
                }
            }
            return result;
        }

        std::string decodeBase64(const std::string &encoded)
        {
            // 255 marks every byte outside the standard Base64 alphabet, including '='.
            // Padding is removed below and is permitted only at the end.
            static constexpr unsigned char lookup[256] = {
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 62,  255, 255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
                255, 255, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
                15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  255, 255, 255, 255, 255, 255, 26,  27,  28,
                29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
                49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            };
            const auto *input = reinterpret_cast<const unsigned char *>(encoded.data());
            const std::size_t size = encoded.size();
            const std::size_t padding = size && input[size - 1] == '=' ? 1 + (size > 1 && input[size - 2] == '=') : 0;
            if (size % 4 == 1 || (padding && size % 4 != 0))
            {
                throw std::invalid_argument("invalid base64");
            }
            const std::size_t content_size = size - padding;
            const std::size_t remainder = content_size % 4;
            std::string result(content_size / 4 * 3 + (remainder ? remainder - 1 : 0), '\0');
            auto *output = &result[0];
            std::uint32_t invalid = 0;
            const auto decode_block = [&] {
                const std::uint32_t a = lookup[input[0]], b = lookup[input[1]];
                const std::uint32_t c = lookup[input[2]], d = lookup[input[3]];
                invalid |= a | b | c | d;
                const std::uint32_t bits = (a << 18) | (b << 12) | (c << 6) | d;
                output[0] = static_cast<char>(bits >> 16);
                output[1] = static_cast<char>((bits >> 8) & 255);
                output[2] = static_cast<char>(bits & 255);
                input += 4;
                output += 3;
            };
            std::size_t remaining = content_size;
            while (remaining >= 4 * batch_groups)
            {
                for (unsigned block = 0; block < batch_groups; ++block)
                {
                    decode_block();
                }
                remaining -= 4 * batch_groups;
            }
            while (remaining >= 4)
            {
                decode_block();
                remaining -= 4;
            }
            if (remaining)
            {
                const std::uint32_t a = lookup[input[0]], b = lookup[input[1]];
                const std::uint32_t c = remaining == 3 ? lookup[input[2]] : 0;
                invalid |= a | b | c;
                output[0] = static_cast<char>((a << 2) | (b >> 4));
                if (remaining == 3)
                {
                    output[1] = static_cast<char>(((b & 15) << 4) | (c >> 2));
                }
            }
            // Valid alphabet entries use only six bits.
            if (invalid > 63)
            {
                throw std::invalid_argument("invalid base64");
            }
            return result;
        }
    } // namespace bindings
} // namespace seal
