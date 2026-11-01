// Licensed under the MIT license.

#pragma once

#include "seal/bindings/base64.h"
#include "seal/seal.h"
#include <cstddef>
#include <cstdint>
#include <emscripten/bind.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace seal
{
    namespace bindings
    {
        EMSCRIPTEN_DECLARE_VAL_TYPE(Uint64Array);
        EMSCRIPTEN_DECLARE_VAL_TYPE(ModOperandArray);
        EMSCRIPTEN_DECLARE_VAL_TYPE(NTTTableArray);
        EMSCRIPTEN_DECLARE_VAL_TYPE(PublicKeyArray);

        template <typename T>
        emscripten::val copyToTypedArray(std::size_t size, const T *data)
        {
            // Copy into a JS-owned buffer before the C++ storage is released or Wasm memory grows.
            emscripten::val view(emscripten::typed_memory_view(size, data));
            return view["constructor"].new_(view);
        }

        std::string typedArrayName(const emscripten::val &data);

        template <typename T>
        std::vector<T> vectorFromTypedArray(const emscripten::val &data, const char *expected_type)
        {
            if (typedArrayName(data) != expected_type)
            {
                throw std::invalid_argument(std::string("expected ") + expected_type);
            }
            return emscripten::convertJSArrayToNumberVector<T>(data);
        }

        template <typename T>
        std::string saveToBase64Helper(const T &self, compr_mode_type mode)
        {
            const std::size_t n = self.save_size(mode);
            std::vector<seal_byte> buf(n);
            const std::size_t written = self.save(buf.data(), buf.size(), mode);
            return encodeBase64(buf.data(), written);
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
            std::string decoded = decodeBase64(encoded);
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
            std::string decoded = decodeBase64(encoded);
            self.load(reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
        }

        template <typename T>
        void loadFromArrayHelperNoContext(T &self, const emscripten::val &data)
        {
            auto buf = vectorFromTypedArray<std::uint8_t>(data, "Uint8Array");
            self.load(reinterpret_cast<const seal_byte *>(buf.data()), buf.size());
        }
    } // namespace bindings
} // namespace seal
