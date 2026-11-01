// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_keys)
{
    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("size", &KSwitchKeys::size)
        .function("saveToBase64", &saveToBase64Helper<KSwitchKeys>)
        .function("saveToArray", &saveToArrayHelper<KSwitchKeys>)
        .function("loadFromBase64", &loadFromBase64Helper<KSwitchKeys>)
        .function("loadFromArray", &loadFromArrayHelper<KSwitchKeys>);

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
}
