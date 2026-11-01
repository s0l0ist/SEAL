// Licensed under the MIT license.

#include "seal/bindings/helpers.h"

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

EMSCRIPTEN_BINDINGS(seal_evaluator)
{
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
}
