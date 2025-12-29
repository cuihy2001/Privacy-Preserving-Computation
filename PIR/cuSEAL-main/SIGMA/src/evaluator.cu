// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "evaluator.cuh"
#include "kernelutils.cuh"
#include "util/common.h"
#include "util/galois.h"
#include "util/numth.h"
#include "util/polyarithsmallmod.h"
#include "util/polycore.h"
#include "util/scalingvariant.h"
#include "util/uintarith.h"
#include <algorithm>
#include <cmath>
#include <functional>

using namespace std;
using namespace sigma::util;
using namespace sigma::kernel_util;

namespace sigma
{
    namespace
    {
        template <typename T, typename S>
        SIGMA_NODISCARD inline bool are_same_scale(const T &value1, const S &value2) noexcept
        {
            return util::are_close<double>(value1.scale(), value2.scale());
        }

        SIGMA_NODISCARD inline bool is_scale_within_bounds(
            double scale, const SIGMAContext::ContextData &context_data) noexcept
        {
            int scale_bit_count_bound = 0;
            switch (context_data.parms().scheme())
            {
            case scheme_type::bfv:
            case scheme_type::bgv:
                scale_bit_count_bound = context_data.parms().plain_modulus().bit_count();
                break;
            case scheme_type::ckks:
                scale_bit_count_bound = context_data.total_coeff_modulus_bit_count();
                break;
            default:
                // Unsupported scheme; check will fail
                scale_bit_count_bound = -1;
            };

            return !(scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
        }

        /**
        Returns (f, e1, e2) such that
        (1) e1 * factor1 = e2 * factor2 = f mod p;
        (2) gcd(e1, p) = 1 and gcd(e2, p) = 1;
        (3) abs(e1_bal) + abs(e2_bal) is minimal, where e1_bal and e2_bal represent e1 and e2 in (-p/2, p/2].
        */
        SIGMA_NODISCARD inline auto balance_correction_factors(
            uint64_t factor1, uint64_t factor2, const Modulus &plain_modulus) -> tuple<uint64_t, uint64_t, uint64_t>
        {
            uint64_t t = plain_modulus.value();
            uint64_t half_t = t / 2;

            auto sum_abs = [&](uint64_t x, uint64_t y) {
                int64_t x_bal = static_cast<int64_t>(x > half_t ? x - t : x);
                int64_t y_bal = static_cast<int64_t>(y > half_t ? y - t : y);
                return abs(x_bal) + abs(y_bal);
            };

            // ratio = f2 / f1 mod p
            uint64_t ratio = 1;
            if (!try_invert_uint_mod(factor1, plain_modulus, ratio))
            {
                throw logic_error("invalid correction factor1");
            }
            ratio = multiply_uint_mod(ratio, factor2, plain_modulus);
            uint64_t e1 = ratio;
            uint64_t e2 = 1;
            int64_t sum = sum_abs(e1, e2);

            // Extended Euclidean
            int64_t prev_a = static_cast<int64_t>(plain_modulus.value());
            int64_t prev_b = static_cast<int64_t>(0);
            int64_t a = static_cast<int64_t>(ratio);
            int64_t b = 1;

            while (a != 0)
            {
                int64_t q = prev_a / a;
                int64_t temp = prev_a % a;
                prev_a = a;
                a = temp;

                temp = sub_safe(prev_b, mul_safe(b, q));
                prev_b = b;
                b = temp;

                uint64_t a_mod = barrett_reduce_64(static_cast<uint64_t>(abs(a)), plain_modulus);
                if (a < 0)
                {
                    a_mod = negate_uint_mod(a_mod, plain_modulus);
                }
                uint64_t b_mod = barrett_reduce_64(static_cast<uint64_t>(abs(b)), plain_modulus);
                if (b < 0)
                {
                    b_mod = negate_uint_mod(b_mod, plain_modulus);
                }
                if (a_mod != 0 && gcd(a_mod, t) == 1) // which also implies gcd(b_mod, t) == 1
                {
                    int64_t new_sum = sum_abs(a_mod, b_mod);
                    if (new_sum < sum)
                    {
                        sum = new_sum;
                        e1 = a_mod;
                        e2 = b_mod;
                    }
                }
            }
            return make_tuple(multiply_uint_mod(e1, factor1, plain_modulus), e1, e2);
        }
    } // namespace

    Evaluator::Evaluator(const SIGMAContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
    }

    void Evaluator::negate_inplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t encrypted_size = encrypted.size();

        // Negate each poly in the array
        negate_poly_coeffmod(encrypted, encrypted_size, coeff_modulus, encrypted);
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::cu_add_inplace(Ciphertext &encrypted1, Ciphertext &encrypted2) const
    {
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);


        //encrypted1.resize(context_, context_data.parms_id(), max_count);
        //encrypted1.copy_to_device();
        //encrypted1.parms_id() = context_data->parms_id();
        //encrypted2.copy_to_device();

        //encrypted1.resize(context_, context_data.parms_id(), max_count);
        // Add ciphertexts
        //#pragma unroll
        for(int i = 0; i < encrypted1_size; i++) {
            for(int j = 0; j < coeff_modulus_size; j++) {
                kernel_util::add_poly_coeffmod(encrypted1.device_data() + i * coeff_modulus_size * coeff_count + j * coeff_count
                                               , encrypted2.device_data() + i * coeff_modulus_size * coeff_count + j * coeff_count
                                               ,1, 1, coeff_count, coeff_modulus[j].value(),
                                               encrypted1.device_data() + i * coeff_modulus_size * coeff_count + j * coeff_count);
            }
        }
        //encrypted1.retrieve_to_host();
        //encrypted2.retrieve_to_host();
    }

    void Evaluator::add_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correction_factor() != encrypted2.correction_factor())
        {
            // Balance correction factors and multiply by scalars before addition in BGV
            auto factors = balance_correction_factors(
                encrypted1.correction_factor(), encrypted2.correction_factor(), plain_modulus);
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted1.data(), coeff_count, coeff_modulus_size), encrypted1.size(), get<1>(factors),
                coeff_modulus, PolyIter(encrypted1.data(), coeff_count, coeff_modulus_size));

            Ciphertext encrypted2_copy = encrypted2;
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted2.data(), coeff_count, coeff_modulus_size), encrypted2.size(), get<2>(factors),
                coeff_modulus, PolyIter(encrypted2_copy.data(), coeff_count, coeff_modulus_size));

            // Set new correction factor
            encrypted1.correction_factor() = get<0>(factors);
            encrypted2_copy.correction_factor() = get<0>(factors);

            add_inplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parms_id(), max_count);
            // Add ciphertexts
            add_poly_coeffmod(encrypted1, encrypted2, min_count, coeff_modulus, encrypted1);

            // Copy the remainding polys of the array with larger count into encrypted1
            if (encrypted1_size < encrypted2_size)
            {
                set_poly_array(
                    encrypted2.data(min_count), encrypted2_size - encrypted1_size, coeff_count, coeff_modulus_size,
                    encrypted1.data(encrypted1_size));
            }
        }

#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        // 暂时注掉, Release下判断条件有问题
//        if (encrypted1.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

   /* void Evaluator::cu_add_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const {
        // Verify parameters.
//        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1)) {
//            throw invalid_argument("encrypted1 is not valid for encryption parameters");
//        }
//        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2)) {
//            throw invalid_argument("encrypted2 is not valid for encryption parameters");
//        }
//        if (encrypted1.parms_id() != encrypted2.parms_id()) {
//            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
//        }
//        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form()) {
//            throw invalid_argument("NTT form mismatch");
//        }
//        if (!are_same_scale(encrypted1, encrypted2)) {
//            throw invalid_argument("scale mismatch");
//        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();

        kernel_util::add_poly_coeffmod(
                encrypted1.device_data(), encrypted2.device_data(), encrypted1_size, coeff_modulus_size,
                coeff_count, coeff_modulus[0].value(), encrypted1.device_data());
    }
*/
    void Evaluator::add_many(const vector<Ciphertext> &encrypteds, Ciphertext &destination) const
    {
        if (encrypteds.empty())
        {
            throw invalid_argument("encrypteds cannot be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        destination = encrypteds[0];
        for (size_t i = 1; i < encrypteds.size(); i++)
        {
            add_inplace(destination, encrypteds[i]);
        }
    }

    void Evaluator::sub_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correction_factor() != encrypted2.correction_factor())
        {
            // Balance correction factors and multiply by scalars before subtraction in BGV
            auto factors = balance_correction_factors(
                encrypted1.correction_factor(), encrypted2.correction_factor(), plain_modulus);

            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted1.data(), coeff_count, coeff_modulus_size), encrypted1.size(), get<1>(factors),
                coeff_modulus, PolyIter(encrypted1.data(), coeff_count, coeff_modulus_size));

            Ciphertext encrypted2_copy = encrypted2;
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted2.data(), coeff_count, coeff_modulus_size), encrypted2.size(), get<2>(factors),
                coeff_modulus, PolyIter(encrypted2_copy.data(), coeff_count, coeff_modulus_size));

            // Set new correction factor
            encrypted1.correction_factor() = get<0>(factors);
            encrypted2_copy.correction_factor() = get<0>(factors);

            sub_inplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parms_id(), max_count);

            // Subtract ciphertexts
            sub_poly_coeffmod(encrypted1, encrypted2, min_count, coeff_modulus, encrypted1);

            // If encrypted2 has larger count, negate remaining entries
            if (encrypted1_size < encrypted2_size)
            {
                negate_poly_coeffmod(
                    iter(encrypted2) + min_count, encrypted2_size - min_count, coeff_modulus,
                    iter(encrypted1) + min_count);
            }
        }

#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted1.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::multiply_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }

        auto context_data_ptr = context_.first_context_data();
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            bfv_multiply(encrypted1, encrypted2, pool);
            break;

        case scheme_type::ckks:
            ckks_multiply(encrypted1, encrypted2, pool);
            break;

        case scheme_type::bgv:
            bgv_multiply(encrypted1, encrypted2, pool);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted1.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::bfv_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (encrypted1.is_ntt_form() || encrypted2.is_ntt_form())
        {
            throw invalid_argument("encrypted1 or encrypted2 cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t base_q_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        uint64_t plain_modulus = parms.plain_modulus().value();

        auto rns_tool = context_data.rns_tool();
        size_t base_Bsk_size = rns_tool->base_Bsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, base_Bsk_m_tilde_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterators for bases
        auto base_q = iter(parms.coeff_modulus());
        auto base_Bsk = iter(rns_tool->base_Bsk()->base());

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = iter(context_data.small_ntt_tables());
        auto base_Bsk_ntt_tables = iter(rns_tool->base_Bsk_ntt_tables());

        // Microsoft SIGMA uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
        // following steps:
        //
        // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
        // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
        // (3) Transform the data to NTT form
        // (4) Compute the ciphertext polynomial product using dyadic multiplication
        // (5) Transform the data back from NTT form
        // (6) Multiply the result by t (plain_modulus)
        // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
        // (8) Use Shenoy-Kumaresan method to convert the result to base q

        // Resize encrypted1 to destination size
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
        // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
        // iterators.
        auto behz_extend_base_convert_to_ntt = [&](auto I) {
            // Make copy of input polynomial (in base q) and convert to NTT form
            // Lazy reduction
            set_poly(get<0>(I), coeff_count, base_q_size, get<1>(I));
            ntt_negacyclic_harvey_lazy(get<1>(I), base_q_size, base_q_ntt_tables);

            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            SIGMA_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconv_m_tilde(get<0>(I), temp, pool);

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->sm_mrq(temp, get<2>(I), pool);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            ntt_negacyclic_harvey_lazy(get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
        };

        // Allocate space for a base q output of behz_extend_base_convert_to_ntt for encrypted1
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted1_q, encrypted1_size, coeff_count, base_q_size, pool);

        // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for encrypted1
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted1_Bsk, encrypted1_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ steps (1)-(3) for encrypted1
        SIGMA_ITERATE(iter(encrypted1, encrypted1_q, encrypted1_Bsk), encrypted1_size, behz_extend_base_convert_to_ntt);

        // Repeat for encrypted2
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted2_q, encrypted2_size, coeff_count, base_q_size, pool);
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted2_Bsk, encrypted2_size, coeff_count, base_Bsk_size, pool);

        SIGMA_ITERATE(iter(encrypted2, encrypted2_q, encrypted2_Bsk), encrypted2_size, behz_extend_base_convert_to_ntt);

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
        SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_Bsk, dest_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts
        SIGMA_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
            size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
            size_t curr_encrypted1_first = I - curr_encrypted2_first;
            // size_t curr_encrypted2_last = I - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            // This lambda function computes the ciphertext product for BFV multiplication. Since we use the BEHZ
            // approach, the multiplication of individual polynomials is done using a dyadic product where the inputs
            // are already in NTT form. The arguments of the lambda function are expected to be as follows:
            //
            // 1. a ConstPolyIter pointing to the beginning of the first input ciphertext (in NTT form)
            // 2. a ConstPolyIter pointing to the beginning of the second input ciphertext (in NTT form)
            // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
            // 4. the size of the base
            // 5. a PolyIter pointing to the beginning of the output ciphertext
            auto behz_ciphertext_product = [&](ConstPolyIter in1_iter, ConstPolyIter in2_iter,
                                               ConstModulusIter base_iter, size_t base_size, PolyIter out_iter) {
                // Create a shifted iterator for the first input
                auto shifted_in1_iter = in1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_in2_iter = reverse_iter(in2_iter + curr_encrypted2_first);

                // Create a shifted iterator for the output
                auto shifted_out_iter = out_iter[I];

                SIGMA_ITERATE(iter(shifted_in1_iter, shifted_reversed_in2_iter), steps, [&](auto J) {
                    SIGMA_ITERATE(iter(J, base_iter, shifted_out_iter), base_size, [&](auto K) {
                        SIGMA_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool);
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), temp);
                        add_poly_coeffmod(temp, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                    });
                });
            };

            // Perform the BEHZ ciphertext product both for base q and base Bsk
            behz_ciphertext_product(encrypted1_q, encrypted2_q, base_q, base_q_size, temp_dest_q);
            behz_ciphertext_product(encrypted1_Bsk, encrypted2_Bsk, base_Bsk, base_Bsk_size, temp_dest_Bsk);
        });

        // Perform BEHZ step (5): transform data from NTT form
        // Lazy reduction here. The following multiply_poly_scalar_coeffmod will correct the value back to [0, p)
        inverse_ntt_negacyclic_harvey_lazy(temp_dest_q, dest_size, base_q_ntt_tables);
        inverse_ntt_negacyclic_harvey_lazy(temp_dest_Bsk, dest_size, base_Bsk_ntt_tables);

        // Perform BEHZ steps (6)-(8)
        SIGMA_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted1), dest_size, [&](auto I) {
            // Bring together the base q and base Bsk components into a single allocation
            SIGMA_ALLOCATE_GET_RNS_ITER(temp_q_Bsk, coeff_count, base_q_size + base_Bsk_size, pool);

            // Step (6): multiply base q components by t (plain_modulus)
            multiply_poly_scalar_coeffmod(get<0>(I), base_q_size, plain_modulus, base_q, temp_q_Bsk);

            multiply_poly_scalar_coeffmod(get<1>(I), base_Bsk_size, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size);

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            SIGMA_ALLOCATE_GET_RNS_ITER(temp_Bsk, coeff_count, base_Bsk_size, pool);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fast_floor(temp_q_Bsk, temp_Bsk, pool);

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconv_sk(temp_Bsk, get<2>(I), pool);
        });
    }

    void Evaluator::ckks_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (!(encrypted1.is_ntt_form() && encrypted2.is_ntt_form()))
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertexts
        PolyIter encrypted1_iter = iter(encrypted1);
        ConstPolyIter encrypted2_iter = iter(encrypted2);

        if (dest_size == 3)
        {
            // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
            // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67 coefficients per polynomial,
            // we should keep the tile size at 682 or below. The tile size must divide coeff_count, i.e. be a power of
            // two. Some testing shows similar performance with tile size 256 and 512, and worse performance on smaller
            // tiles. We pick the smaller of the two to prevent L1 cache misses on processors with < 32 KiB L1 cache.
            size_t tile_size = min<size_t>(coeff_count, size_t(256));
            size_t num_tiles = coeff_count / tile_size;
#ifdef SIGMA_DEBUG
            if (coeff_count % tile_size != 0)
            {
                throw invalid_argument("tile_size does not divide coeff_count");
            }
#endif

            // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor in sequence
            ConstRNSIter encrypted2_0_iter(*encrypted2_iter[0], tile_size);
            ConstRNSIter encrypted2_1_iter(*encrypted2_iter[1], tile_size);
            RNSIter encrypted1_0_iter(*encrypted1_iter[0], tile_size);
            RNSIter encrypted1_1_iter(*encrypted1_iter[1], tile_size);
            RNSIter encrypted1_2_iter(*encrypted1_iter[2], tile_size);

            // Temporary buffer to store intermediate results
            SIGMA_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

            // Computes the output tile_size coefficients at a time
            // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
            // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
            // with appropriate modular reduction
            SIGMA_ITERATE(coeff_modulus, coeff_modulus_size, [&](auto I) {
                SIGMA_ITERATE(iter(size_t(0)), num_tiles, [&](SIGMA_MAYBE_UNUSED auto J) {
                    // Compute third output polynomial, overwriting input
                    // x[2] = x[1] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_1_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_2_iter[0]);

                    // Compute second output polynomial, overwriting input
                    // temp = x[1] * y[0]
                    dyadic_product_coeffmod(encrypted1_1_iter[0], encrypted2_0_iter[0], tile_size, I, temp);
                    // x[1] = x[0] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_1_iter[0]);
                    // x[1] += temp
                    add_poly_coeffmod(encrypted1_1_iter[0], temp, tile_size, I, encrypted1_1_iter[0]);

                    // Compute first output polynomial, overwriting input
                    // x[0] = x[0] * y[0]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_0_iter[0], tile_size, I, encrypted1_0_iter[0]);

                    // Manually increment iterators
                    encrypted1_0_iter++;
                    encrypted1_1_iter++;
                    encrypted1_2_iter++;
                    encrypted2_0_iter++;
                    encrypted2_1_iter++;
                });
            });
        }
        else
        {
            // Allocate temporary space for the result
            SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

            SIGMA_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
                // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
                // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
                // the relevant terms are obtained as follows.
                size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
                size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
                size_t curr_encrypted1_first = I - curr_encrypted2_first;
                // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_encrypted2_iter = reverse_iter(encrypted2_iter + curr_encrypted2_first);

                SIGMA_ITERATE(iter(shifted_encrypted1_iter, shifted_reversed_encrypted2_iter), steps, [&](auto J) {
                    // Extra care needed here:
                    // temp_iter must be dereferenced once to produce an appropriate RNSIter
                    SIGMA_ITERATE(iter(J, coeff_modulus, temp[I]), coeff_modulus_size, [&](auto K) {
                        SIGMA_ALLOCATE_GET_COEFF_ITER(prod, coeff_count, pool);
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), prod);
                        add_poly_coeffmod(prod, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                    });
                });
            });

            // Set the final result
            set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, encrypted1.data());
        }

        // Set the scale
        encrypted1.scale() *= encrypted2.scale();
        if (!is_scale_within_bounds(encrypted1.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgv_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (!encrypted1.is_ntt_form() || !encrypted2.is_ntt_form())
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // Convert c0 and c1 to ntt
        // Set up iterators for input ciphertexts
        PolyIter encrypted1_iter = iter(encrypted1);
        ConstPolyIter encrypted2_iter = iter(encrypted2);

        if (dest_size == 3)
        {
            // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
            // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67 coefficients per polynomial,
            // we should keep the tile size at 682 or below. The tile size must divide coeff_count, i.e. be a power of
            // two. Some testing shows similar performance with tile size 256 and 512, and worse performance on smaller
            // tiles. We pick the smaller of the two to prevent L1 cache misses on processors with < 32 KiB L1 cache.
            size_t tile_size = min<size_t>(coeff_count, size_t(256));
            size_t num_tiles = coeff_count / tile_size;
#ifdef SIGMA_DEBUG
            if (coeff_count % tile_size != 0)
            {
                throw invalid_argument("tile_size does not divide coeff_count");
            }
#endif

            // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor in sequence
            ConstRNSIter encrypted2_0_iter(*encrypted2_iter[0], tile_size);
            ConstRNSIter encrypted2_1_iter(*encrypted2_iter[1], tile_size);
            RNSIter encrypted1_0_iter(*encrypted1_iter[0], tile_size);
            RNSIter encrypted1_1_iter(*encrypted1_iter[1], tile_size);
            RNSIter encrypted1_2_iter(*encrypted1_iter[2], tile_size);

            // Temporary buffer to store intermediate results
            SIGMA_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

            // Computes the output tile_size coefficients at a time
            // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
            // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
            // with appropriate modular reduction
            SIGMA_ITERATE(coeff_modulus, coeff_modulus_size, [&](auto I) {
                SIGMA_ITERATE(iter(size_t(0)), num_tiles, [&](SIGMA_MAYBE_UNUSED auto J) {
                    // Compute third output polynomial, overwriting input
                    // x[2] = x[1] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_1_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_2_iter[0]);

                    // Compute second output polynomial, overwriting input
                    // temp = x[1] * y[0]
                    dyadic_product_coeffmod(encrypted1_1_iter[0], encrypted2_0_iter[0], tile_size, I, temp);
                    // x[1] = x[0] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_1_iter[0]);
                    // x[1] += temp
                    add_poly_coeffmod(encrypted1_1_iter[0], temp, tile_size, I, encrypted1_1_iter[0]);

                    // Compute first output polynomial, overwriting input
                    // x[0] = x[0] * y[0]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_0_iter[0], tile_size, I, encrypted1_0_iter[0]);

                    // Manually increment iterators
                    encrypted1_0_iter++;
                    encrypted1_1_iter++;
                    encrypted1_2_iter++;
                    encrypted2_0_iter++;
                    encrypted2_1_iter++;
                });
            });
        }
        else
        {
            // Allocate temporary space for the result
            SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

            SIGMA_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
                // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
                // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
                // the relevant terms are obtained as follows.
                size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
                size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
                size_t curr_encrypted1_first = I - curr_encrypted2_first;
                // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_encrypted2_iter = reverse_iter(encrypted2_iter + curr_encrypted2_first);

                SIGMA_ITERATE(iter(shifted_encrypted1_iter, shifted_reversed_encrypted2_iter), steps, [&](auto J) {
                    // Extra care needed here:
                    // temp_iter must be dereferenced once to produce an appropriate RNSIter
                    SIGMA_ITERATE(iter(J, coeff_modulus, temp[I]), coeff_modulus_size, [&](auto K) {
                        SIGMA_ALLOCATE_GET_COEFF_ITER(prod, coeff_count, pool);
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), prod);
                        add_poly_coeffmod(prod, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                    });
                });
            });

            // Set the final result
            set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, encrypted1.data());
        }

        // Set the correction factor
        encrypted1.correction_factor() =
            multiply_uint_mod(encrypted1.correction_factor(), encrypted2.correction_factor(), parms.plain_modulus());
    }

    void Evaluator::square_inplace(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.first_context_data();
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            bfv_square(encrypted, move(pool));
            break;

        case scheme_type::ckks:
            ckks_square(encrypted, move(pool));
            break;

        case scheme_type::bgv:
            bgv_square(encrypted, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::bfv_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t base_q_size = parms.coeff_modulus().size();
        size_t encrypted_size = encrypted.size();
        uint64_t plain_modulus = parms.plain_modulus().value();

        auto rns_tool = context_data.rns_tool();
        size_t base_Bsk_size = rns_tool->base_Bsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bfv_multiply(encrypted, encrypted, move(pool));
            return;
        }

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, base_Bsk_m_tilde_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterators for bases
        auto base_q = iter(parms.coeff_modulus());
        auto base_Bsk = iter(rns_tool->base_Bsk()->base());

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = iter(context_data.small_ntt_tables());
        auto base_Bsk_ntt_tables = iter(rns_tool->base_Bsk_ntt_tables());

        // Microsoft SIGMA uses BEHZ-style RNS multiplication. For details, see Evaluator::bfv_multiply. This function
        // uses additionally Karatsuba multiplication to reduce the complexity of squaring a size-2 ciphertext, but the
        // steps are otherwise the same as in Evaluator::bfv_multiply.

        // Resize encrypted to destination size
        encrypted.resize(context_, context_data.parms_id(), dest_size);

        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication on the given input polynomial (given as an RNSIter
        // or ConstRNSIter) and writes the results in base q and base Bsk to the given output iterators.
        auto behz_extend_base_convert_to_ntt = [&](auto I) {
            // Make copy of input polynomial (in base q) and convert to NTT form
            // Lazy reduction
            set_poly(get<0>(I), coeff_count, base_q_size, get<1>(I));
            ntt_negacyclic_harvey_lazy(get<1>(I), base_q_size, base_q_ntt_tables);

            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            SIGMA_ALLOCATE_GET_RNS_ITER(temp, coeff_count, base_Bsk_m_tilde_size, pool);

            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool->fastbconv_m_tilde(get<0>(I), temp, pool);

            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            rns_tool->sm_mrq(temp, get<2>(I), pool);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            ntt_negacyclic_harvey_lazy(get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
        };

        // Allocate space for a base q output of behz_extend_base_convert_to_ntt
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted_q, encrypted_size, coeff_count, base_q_size, pool);

        // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt
        SIGMA_ALLOCATE_GET_POLY_ITER(encrypted_Bsk, encrypted_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ steps (1)-(3)
        SIGMA_ITERATE(iter(encrypted, encrypted_q, encrypted_Bsk), encrypted_size, behz_extend_base_convert_to_ntt);

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
        SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp_dest_Bsk, dest_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ step (4): dyadic Karatsuba-squaring on size-2 ciphertexts

        // This lambda function computes the size-2 ciphertext square for BFV multiplication. Since we use the BEHZ
        // approach, the multiplication of individual polynomials is done using a dyadic product where the inputs
        // are already in NTT form. The arguments of the lambda function are expected to be as follows:
        //
        // 1. a ConstPolyIter pointing to the beginning of the input ciphertext (in NTT form)
        // 3. a ConstModulusIter pointing to an array of Modulus elements for the base
        // 4. the size of the base
        // 5. a PolyIter pointing to the beginning of the output ciphertext
        auto behz_ciphertext_square = [&](ConstPolyIter in_iter, ConstModulusIter base_iter, size_t base_size,
                                          PolyIter out_iter) {
            // Compute c0^2
            dyadic_product_coeffmod(in_iter[0], in_iter[0], base_size, base_iter, out_iter[0]);

            // Compute 2*c0*c1
            dyadic_product_coeffmod(in_iter[0], in_iter[1], base_size, base_iter, out_iter[1]);
            add_poly_coeffmod(out_iter[1], out_iter[1], base_size, base_iter, out_iter[1]);

            // Compute c1^2
            dyadic_product_coeffmod(in_iter[1], in_iter[1], base_size, base_iter, out_iter[2]);
        };

        // Perform the BEHZ ciphertext square both for base q and base Bsk
        behz_ciphertext_square(encrypted_q, base_q, base_q_size, temp_dest_q);
        behz_ciphertext_square(encrypted_Bsk, base_Bsk, base_Bsk_size, temp_dest_Bsk);

        // Perform BEHZ step (5): transform data from NTT form
        inverse_ntt_negacyclic_harvey(temp_dest_q, dest_size, base_q_ntt_tables);
        inverse_ntt_negacyclic_harvey(temp_dest_Bsk, dest_size, base_Bsk_ntt_tables);

        // Perform BEHZ steps (6)-(8)
        SIGMA_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted), dest_size, [&](auto I) {
            // Bring together the base q and base Bsk components into a single allocation
            SIGMA_ALLOCATE_GET_RNS_ITER(temp_q_Bsk, coeff_count, base_q_size + base_Bsk_size, pool);

            // Step (6): multiply base q components by t (plain_modulus)
            multiply_poly_scalar_coeffmod(get<0>(I), base_q_size, plain_modulus, base_q, temp_q_Bsk);

            multiply_poly_scalar_coeffmod(get<1>(I), base_Bsk_size, plain_modulus, base_Bsk, temp_q_Bsk + base_q_size);

            // Allocate yet another temporary for fast divide-and-floor result in base Bsk
            SIGMA_ALLOCATE_GET_RNS_ITER(temp_Bsk, coeff_count, base_Bsk_size, pool);

            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool->fast_floor(temp_q_Bsk, temp_Bsk, pool);

            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool->fastbconv_sk(temp_Bsk, get<2>(I), pool);
        });
    }

    void Evaluator::ckks_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            ckks_multiply(encrypted, encrypted, move(pool));
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertext
        auto encrypted_iter = iter(encrypted);

        // Compute c1^2
        dyadic_product_coeffmod(
            encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[2]);

        // Compute 2*c0*c1
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);
        add_poly_coeffmod(encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);

        // Compute c0^2
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[0], coeff_modulus_size, coeff_modulus, encrypted_iter[0]);

        // Set the scale
        encrypted.scale() *= encrypted.scale();
        if (!is_scale_within_bounds(encrypted.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgv_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bgv_multiply(encrypted, encrypted, move(pool));
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertext
        auto encrypted_iter = iter(encrypted);

        // Allocate temporary space for the result
        SIGMA_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

        // Compute c1^2
        dyadic_product_coeffmod(
            encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[2]);

        // Compute 2*c0*c1
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);
        add_poly_coeffmod(encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);

        // Compute c0^2
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[0], coeff_modulus_size, coeff_modulus, encrypted_iter[0]);

        // Set the correction factor
        encrypted.correction_factor() =
            multiply_uint_mod(encrypted.correction_factor(), encrypted.correction_factor(), parms.plain_modulus());
    }

    void Evaluator::relinearize_internal(
        Ciphertext &encrypted, const RelinKeys &relin_keys, size_t destination_size, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (relin_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }

        size_t encrypted_size = encrypted.size();

        // Verify parameters.
        if (destination_size < 2 || destination_size > encrypted_size)
        {
            throw invalid_argument("destination_size must be at least 2 and less than or equal to current count");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough relinearization keys");
        }

        // If encrypted is already at the desired level, return
        if (destination_size == encrypted_size)
        {
            return;
        }

        // Calculate number of relinearize_one_step calls needed
        size_t relins_needed = encrypted_size - destination_size;

        // Iterator pointing to the last component of encrypted
        auto encrypted_iter = iter(encrypted);
        encrypted_iter += encrypted_size - 1;

        SIGMA_ITERATE(iter(size_t(0)), relins_needed, [&](auto I) {
            this->switch_key_inplace(
                encrypted, *encrypted_iter, static_cast<const KSwitchKeys &>(relin_keys),
                RelinKeys::get_index(encrypted_size - 1 - I), pool);
        });

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        encrypted.resize(context_, context_data_ptr->parms_id(), destination_size);
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::mod_switch_scale_to_next(
        const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::bfv && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::ckks && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::bgv && !encrypted.is_ntt_form())
        {
            throw invalid_argument("BGV encrypted must be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &next_context_data = *context_data.next_context_data();
        auto &next_parms = next_context_data.parms();
        auto rns_tool = context_data.rns_tool();

        size_t encrypted_size = encrypted.size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t next_coeff_modulus_size = next_parms.coeff_modulus().size();

        Ciphertext encrypted_copy(pool);
        encrypted_copy = encrypted;

        encrypted_copy.copy_to_device();

        switch (next_parms.scheme())
        {
        case scheme_type::bfv:
            for(int i = 0; i < encrypted_size; i++){
                rns_tool->divideAndRoundqLastInplace(encrypted_copy.device_data() + encrypted_copy.coeff_modulus_size()
                * encrypted_copy.poly_modulus_degree() * i);
                //rns_tool->divideAndRoundqLastInplace(encrypted_copy.device_data(i));
            }
            /*SIGMA_ITERATE(iter(encrypted_copy.device_data()), encrypted_size, [&](auto I) {
                rns_tool->divideAndRoundqLastInplace(I);
                //rns_tool->divide_and_round_q_last_inplace(I, pool);
            });*/
            break;

        case scheme_type::ckks:
            SIGMA_ITERATE(iter(encrypted_copy), encrypted_size, [&](auto I) {
                rns_tool->divide_and_round_q_last_ntt_inplace(I, context_data.small_ntt_tables(), pool);
            });
            break;

        case scheme_type::bgv:
            SIGMA_ITERATE(iter(encrypted_copy), encrypted_size, [&](auto I) {
                rns_tool->mod_t_and_divide_q_last_ntt_inplace(I, context_data.small_ntt_tables(), pool);
            });
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }

        encrypted_copy.retrieve_to_host();
        // Copy result to destination
        destination.resize(context_, next_context_data.parms_id(), encrypted_size);
        SIGMA_ITERATE(iter(encrypted_copy, destination), encrypted_size, [&](auto I) {
            set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I));
        });

        // Set other attributes
        destination.is_ntt_form() = encrypted.is_ntt_form();
        if (next_parms.scheme() == scheme_type::ckks)
        {
            // Change the scale when using CKKS
            destination.scale() =
                encrypted.scale() / static_cast<double>(context_data.parms().coeff_modulus().back().value());
        }
        else if (next_parms.scheme() == scheme_type::bgv)
        {
            // Change the correction factor when using BGV
            destination.correction_factor() = multiply_uint_mod(
                encrypted.correction_factor(), rns_tool->inv_q_last_mod_t(), next_parms.plain_modulus());
        }
    }

    void Evaluator::mod_switch_drop_to_next(
        const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::ckks && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = next_context_data.parms();

        if (!is_scale_within_bounds(encrypted.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        size_t next_coeff_modulus_size = next_parms.coeff_modulus().size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, next_coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        auto drop_modulus_and_copy = [&](ConstPolyIter in_iter, PolyIter out_iter) {
            SIGMA_ITERATE(iter(in_iter, out_iter), encrypted_size, [&](auto I) {
                SIGMA_ITERATE(
                    iter(I), next_coeff_modulus_size, [&](auto J) { set_uint(get<0>(J), coeff_count, get<1>(J)); });
            });
        };

        if (&encrypted == &destination)
        {
            // Switching in-place so need temporary space
            SIGMA_ALLOCATE_GET_POLY_ITER(temp, encrypted_size, coeff_count, next_coeff_modulus_size, pool);

            // Copy data over to temp; only copy the RNS components relevant after modulus drop
            drop_modulus_and_copy(encrypted, temp);

            // Resize destination before writing
            destination.resize(context_, next_context_data.parms_id(), encrypted_size);

            // Copy data to destination
            set_poly_array(temp, encrypted_size, coeff_count, next_coeff_modulus_size, destination.data());
            // TODO: avoid copying and temporary space allocation
        }
        else
        {
            // Resize destination before writing
            destination.resize(context_, next_context_data.parms_id(), encrypted_size);

            // Copy data over to destination; only copy the RNS components relevant after modulus drop
            drop_modulus_and_copy(encrypted, destination);
        }
        destination.is_ntt_form() = true;
        destination.scale() = encrypted.scale();
        destination.correction_factor() = encrypted.correction_factor();
    }

    void Evaluator::mod_switch_drop_to_next(Plaintext &plain) const
    {
        // Assuming at this point plain is already validated.
        auto context_data_ptr = context_.get_context_data(plain.parms_id());
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (!context_data_ptr->next_context_data())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = context_data_ptr->next_context_data()->parms();

        if (!is_scale_within_bounds(plain.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeff_modulus();
        size_t next_coeff_modulus_size = next_coeff_modulus.size();
        size_t coeff_count = next_parms.poly_modulus_degree();

        // Compute destination size first for exception safety
        auto dest_size = mul_safe(next_coeff_modulus_size, coeff_count);

        plain.parms_id() = parms_id_zero;
        plain.resize(dest_size);
        plain.parms_id() = next_context_data.parms_id();
    }

    void Evaluator::mod_switch_to_next(
        const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_.first_context_data()->parms().scheme())
        {
        case scheme_type::bfv:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, move(pool));
            break;

        case scheme_type::ckks:
            // Modulus switching without scaling
            mod_switch_drop_to_next(encrypted, destination, move(pool));
            break;

        case scheme_type::bgv:
            mod_switch_scale_to_next(encrypted, destination, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (destination.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::mod_switch_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(encrypted, pool);
        }
    }

    void Evaluator::cu_mod_switch_to_inplace(Ciphertext &encrypted, parms_id_type parms_id)
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);

        auto &context_data = *context_data_ptr;
        auto &next_context_data = *context_data.next_context_data();
        auto &parms = context_data.parms();
        auto &next_parms = next_context_data.parms();
        auto rns_tool = context_data.rns_tool();

        size_t encrypted_size = encrypted.size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t next_coeff_modulus_size = next_parms.coeff_modulus().size();

        //encrypted.copy_to_device();

        Ciphertext encrypted_copy;
        encrypted_copy = encrypted;

        encrypted_copy.copy_to_device();


        for(int i = 0; i < encrypted_size; i++){
            rns_tool->divideAndRoundqLastInplace(encrypted_copy.device_data() + encrypted_copy.coeff_modulus_size()
            * encrypted_copy.poly_modulus_degree() * i);
                    //rns_tool->divideAndRoundqLastInplace(encrypted_copy.device_data(i));
        }

        //encrypted_copy.retrieve_to_host();
        // Copy result to destination
        encrypted.resize(context_, next_context_data.parms_id(), encrypted_size);
        encrypted.copy_to_device();
        /*SIGMA_ITERATE(iter(encrypted_copy, encrypted), encrypted_size, [&](auto I) {
            set_poly(get<0>(I), coeff_count, next_coeff_modulus_size, get<1>(I));
        });*/
        for(int i = 0; i < encrypted_size; i++) {
            KernelProvider::copyOnDevice(encrypted.device_data() + i * coeff_count * next_coeff_modulus_size,
                                         encrypted_copy.device_data() + i * coeff_count * coeff_modulus_size,
                                         coeff_count * next_coeff_modulus_size);

        }
        //encrypted.retrieve_to_host();
        // Set other attributes
    }


    void Evaluator::mod_switch_to_inplace(Plaintext &plain, parms_id_type parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(plain.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_.get_context_data(parms_id))
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (plain.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(plain);
        }
    }

    void Evaluator::rescale_to_next(const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_.first_context_data()->parms().scheme())
        {
        case scheme_type::bfv:
            /* Fall through */
        case scheme_type::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::ckks:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (destination.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::rescale_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            /* Fall through */
        case scheme_type::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::ckks:
            while (encrypted.parms_id() != parms_id)
            {
                // Modulus switching with scaling
                mod_switch_scale_to_next(encrypted, encrypted, pool);
            }
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::mod_reduce_to_next_inplace(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        mod_switch_drop_to_next(encrypted, encrypted, std::move(pool));
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::mod_reduce_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parms_id() != parms_id)
        {
            mod_reduce_to_next_inplace(encrypted, pool);
        }
    }

    void Evaluator::multiply_many(
        const vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys, Ciphertext &destination,
        MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (encrypteds.size() == 0)
        {
            throw invalid_argument("encrypteds vector must not be empty");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // There is at least one ciphertext
        auto context_data_ptr = context_.get_context_data(encrypteds[0].parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();

        if (parms.scheme() != scheme_type::bfv && parms.scheme() != scheme_type::bgv)
        {
            throw logic_error("unsupported scheme");
        }

        // If there is only one ciphertext, return it.
        if (encrypteds.size() == 1)
        {
            destination = encrypteds[0];
            return;
        }

        // Do first level of multiplications
        vector<Ciphertext> product_vec;
        for (size_t i = 0; i < encrypteds.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parms_id(), pool);
            if (encrypteds[i].data() == encrypteds[i + 1].data())
            {
                square(encrypteds[i], temp);
            }
            else
            {
                multiply(encrypteds[i], encrypteds[i + 1], temp);
            }
            relinearize_inplace(temp, relin_keys, pool);
            product_vec.emplace_back(move(temp));
        }
        if (encrypteds.size() & 1)
        {
            product_vec.emplace_back(encrypteds.back());
        }

        // Repeatedly multiply and add to the back of the vector until the end is reached
        for (size_t i = 0; i < product_vec.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parms_id(), pool);
            multiply(product_vec[i], product_vec[i + 1], temp);
            relinearize_inplace(temp, relin_keys, pool);
            product_vec.emplace_back(move(temp));
        }

        destination = product_vec.back();
    }

    void Evaluator::exponentiate_inplace(
        Ciphertext &encrypted, uint64_t exponent, const RelinKeys &relin_keys, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.get_context_data(relin_keys.parms_id()))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (exponent == 0)
        {
            throw invalid_argument("exponent cannot be 0");
        }

        // Fast case
        if (exponent == 1)
        {
            return;
        }

        // Create a vector of copies of encrypted
        vector<Ciphertext> exp_vector(static_cast<size_t>(exponent), encrypted);
        multiply_many(exp_vector, relin_keys, encrypted, move(pool));
    }

    void Evaluator::add_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::bfv)
        {
            if (encrypted.is_ntt_form())
            {
                throw invalid_argument("BFV encrypted cannot be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BFV plain cannot be in NTT form");
            }
        }
        else if (parms.scheme() == scheme_type::ckks)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("CKKS encrypted must be in NTT form");
            }
            if (!plain.is_ntt_form())
            {
                throw invalid_argument("CKKS plain must be in NTT form");
            }
            if (encrypted.parms_id() != plain.parms_id())
            {
                throw invalid_argument("encrypted and plain parameter mismatch");
            }
            if (!are_same_scale(encrypted, plain))
            {
                throw invalid_argument("scale mismatch");
            }
        }
        else if (parms.scheme() == scheme_type::bgv)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("BGV encrypted must be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BGV plain cannot be in NTT form");
            }
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::bfv:
        {
            multiply_add_plain_with_scaling_variant(plain, context_data, *iter(encrypted));
            break;
        }

        case scheme_type::ckks:
        {
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain.data(), coeff_count);
            add_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        case scheme_type::bgv:
        {
            Plaintext plain_copy = plain;
            multiply_poly_scalar_coeffmod(
                plain.data(), plain.coeff_count(), encrypted.correction_factor(), parms.plain_modulus(),
                plain_copy.data());
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), move(pool));
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain_copy.data(), coeff_count);
            add_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::sub_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::bfv)
        {
            if (encrypted.is_ntt_form())
            {
                throw invalid_argument("BFV encrypted cannot be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BFV plain cannot be in NTT form");
            }
        }
        else if (parms.scheme() == scheme_type::ckks)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("CKKS encrypted must be in NTT form");
            }
            if (!plain.is_ntt_form())
            {
                throw invalid_argument("CKKS plain must be in NTT form");
            }
            if (encrypted.parms_id() != plain.parms_id())
            {
                throw invalid_argument("encrypted and plain parameter mismatch");
            }
            if (!are_same_scale(encrypted, plain))
            {
                throw invalid_argument("scale mismatch");
            }
        }
        else if (parms.scheme() == scheme_type::bgv)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("BGV encrypted must be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BGV plain cannot be in NTT form");
            }
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::bfv:
        {
            multiply_sub_plain_with_scaling_variant(plain, context_data, *iter(encrypted));
            break;
        }

        case scheme_type::ckks:
        {
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain.data(), coeff_count);
            sub_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        case scheme_type::bgv:
        {
            Plaintext plain_copy = plain;
            multiply_poly_scalar_coeffmod(
                plain.data(), plain.coeff_count(), encrypted.correction_factor(), parms.plain_modulus(),
                plain_copy.data());
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), move(pool));
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain_copy.data(), coeff_count);
            sub_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::multiply_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

//        std::cout << "Encode and encrypt start" << std::endl;
//        auto time_start = std::chrono::high_resolution_clock::now();

        if (encrypted.is_ntt_form() && plain.is_ntt_form())
        {
            multiply_plain_ntt(encrypted, plain);
        }
        else if (!encrypted.is_ntt_form() && !plain.is_ntt_form())
        {
            multiply_plain_normal(encrypted, plain, move(pool));
        }
        else if (encrypted.is_ntt_form() && !plain.is_ntt_form())
        {
            Plaintext plain_copy = plain;
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), move(pool));
            multiply_plain_ntt(encrypted, plain_copy);
        }
        else
        {
            transform_to_ntt_inplace(encrypted);
            multiply_plain_ntt(encrypted, plain);
            transform_from_ntt_inplace(encrypted);
        }

//        auto time_end = std::chrono::high_resolution_clock::now();
//        auto time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
//        std::cout << "Encode and encrypt end [" << time_diff.count() << " microseconds]" << std::endl;

#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        // 暂时注掉, Release下判断条件有问题
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }


    void Evaluator::cu_multiply_plain_ntt(
             Ciphertext &encrypted_ntt, Plaintext &plain_ntt) {

        auto &context_data = *context_.get_context_data(encrypted_ntt.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        kernel_util::dyadic_product_coeffmod_optimize(encrypted_ntt.device_data(), plain_ntt.device_data() ,
                                         coeff_count, encrypted_ntt_size, coeff_modulus_size, coeff_modulus[0],
                                         encrypted_ntt.device_data());

        CHECK(cudaGetLastError());

        //encrypted_ntt.retrieve_to_host();
        // Set the scale
        encrypted_ntt.scale() *= plain_ntt.scale();

    }


    __global__ void g_set_multiply_uInt_mod_operand(uint64_t scalar, const Modulus* moduli, size_t n, MultiplyUIntModOperand* result) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        uint64_t reduced = d_barrett_reduce_64(scalar, moduli[tid]);
        //printf("%d ", moduli[tid]);
        result[tid].operand = reduced;
        std::uint64_t wide_quotient[2]{ 0, 0 };
        std::uint64_t wide_coeff[2]{ 0, result[tid].operand };
        dDivideUint128Inplace(wide_coeff, moduli[tid].value(), wide_quotient);
        result[tid].quotient = wide_quotient[0];
    }

    __global__ void g_multiply_poly_scalar_coeffmod(
            const uint64_t* poly_array,
            size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result)
    {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        for(int i = 0; i < coeff_modulus_size; i++){
            for(int j = 0; j < poly_size; j++) {
                size_t id = (j * coeff_modulus_size + i) * poly_modulus_degree + tid;
                result[id] = d_multiply_uint_mod(poly_array[id], reduced_scalar[i], modulus[i]);
            }
        }
    }

    __global__ void g_negacyclic_shift_poly_coeffmod(
            const uint64_t *poly,
            size_t coeff_count,
            size_t shift,
            size_t coeff_mod_count,
            const Modulus *modulus,
            uint64_t *result
    ) {
        //GET_INDEX_COND_RETURN(poly_modulus_degree);
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        //if(tid<10)
        //printf("%d ",tid);
        uint64_t index_raw = shift + tid;
        uint64_t index = index_raw & (static_cast<uint64_t>(coeff_count) - 1);
        for (int i = 0; i < coeff_mod_count; i++) {
            const uint64_t modulusValue = (modulus[i]).value();
            size_t id = i * coeff_count + tid;
            size_t rid = i * coeff_count + index;
/*             if(tid==0)
                 printf("%d \n",id);*/
            if (shift == 0) {
                result[id] = poly[id];
            } else {
                if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !poly[id]) {
                    result[rid] = poly[id];
                } else {
                    result[rid] = modulusValue - poly[id];
                }
            }


        }

    }

    void d_negacyclic_shift_poly_coeffmod(
            uint64_t *poly,
            size_t coeff_count,//N
            size_t shift,
            size_t coeff_mod_count,
            const Modulus* modulus,
            uint64_t *result
    ) {

        size_t blocknumber = ceil(coeff_count / 256.0);
        g_negacyclic_shift_poly_coeffmod<<<blocknumber, 256>>>(poly, coeff_count, shift, coeff_mod_count, modulus, result);
        CHECK(cudaGetLastError());

        /*for(int i = 0; i < 4096; i++){
            printf("%d ",result);
        }*/
    }

    void d_multiply_poly_scalar_coeffmod(uint64_t* poly_array, size_t poly_size, size_t coeff_modulus_size,
                                     size_t poly_modulus_degree, uint64_t scalar, const Modulus* modulus, uint64_t* result)
    {
        util::DeviceArray<MultiplyUIntModOperand> reduced_scalar(coeff_modulus_size);
        //printf("%d ", modulus->value());
        //assert(coeff_modulus_size <= 256);
        g_set_multiply_uInt_mod_operand<<<1, coeff_modulus_size>>>(scalar, modulus, coeff_modulus_size, reduced_scalar.get());
        HostArray<MultiplyUIntModOperand> hreduced_scalar(coeff_modulus_size);
        int blocknum = ceil(poly_modulus_degree / 1024.0);
        g_multiply_poly_scalar_coeffmod<<<blocknum, 1024>>>(
                poly_array, poly_size, coeff_modulus_size,
                poly_modulus_degree, reduced_scalar.get(),
                modulus, result);
    }

    void negacyclic_multiply_polymono_coeffmod(
            uint64_t* poly, std::size_t poly_size, std::size_t coeff_count, std::uint64_t coeff_modulus_size, std::uint64_t mono_coeff, std::size_t mono_exponent,
            ConstModulusIter modulus, uint64_t* result)
    {

        // FIXME: Frequent allocation
        for(int i = 0; i < poly_size; i++) {
            for(int j = 0; j < coeff_modulus_size; j++) {
                uint64_t *temp = KernelProvider::malloc<uint64_t>(coeff_count);
                d_multiply_poly_scalar_coeffmod(poly + i * coeff_count * coeff_modulus_size + j * coeff_count
                                            , 1, 1, coeff_count, mono_coeff, &modulus[j], temp);
                d_negacyclic_shift_poly_coeffmod(temp, coeff_count, mono_exponent, 1, &modulus[j],
                                             result + i * coeff_count * coeff_modulus_size + j * coeff_count);
            }
        }
    }

    void Evaluator::cu_multiply_plain_normal(Ciphertext &encrypted, Plaintext &plain)
    {
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.device_coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();
        auto ntt_tables = iter(context_data.small_ntt_tables());

        size_t encrypted_size = encrypted.size();


        size_t mono_exponent = plain.significant_coeff_count() - 1;

        negacyclic_multiply_polymono_coeffmod(
                encrypted.device_data(), encrypted_size, coeff_count, coeff_modulus_size,
                plain[mono_exponent], mono_exponent, coeff_modulus.get(), encrypted.device_data());
    }

    void Evaluator::cu_multiply_plain(Ciphertext &encrypted, Plaintext &plain, Ciphertext &destination) {

        destination.copy_attributes(encrypted);
        destination.alloc_device_data();
        KernelProvider::copyOnDevice(destination.device_data(), encrypted.device_data(),
                                     destination.size() * destination.coeff_modulus_size() * destination.poly_modulus_degree());


        if (encrypted.is_ntt_form() && plain.is_ntt_form())
        {
            cu_multiply_plain_ntt(destination, plain);

        }
        else {
            cu_multiply_plain_normal(destination, plain);
        }

    }

    void Evaluator::multiply_plain_normal(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();
        auto ntt_tables = iter(context_data.small_ntt_tables());

        size_t encrypted_size = encrypted.size();
        size_t plain_coeff_count = plain.coeff_count();
        size_t plain_nonzero_coeff_count = plain.nonzero_coeff_count();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        /*
        Optimizations for constant / monomial multiplication can lead to the presence of a timing side-channel in
        use-cases where the plaintext data should also be kept private.
        */
        if (plain_nonzero_coeff_count == 1)
        {
            // Multiplying by a monomial?
            size_t mono_exponent = plain.significant_coeff_count() - 1;

            if (plain[mono_exponent] >= plain_upper_half_threshold)
            {
                if (!context_data.qualifiers().using_fast_plain_lift)
                {
                    // Allocate temporary space for a single RNS coefficient
                    SIGMA_ALLOCATE_GET_COEFF_ITER(temp, coeff_modulus_size, pool);

                    // We need to adjust the monomial modulo each coeff_modulus prime separately when the coeff_modulus
                    // primes may be larger than the plain_modulus. We add plain_upper_half_increment (i.e., q-t) to
                    // the monomial to ensure it is smaller than coeff_modulus and then do an RNS multiplication. Note
                    // that in this case plain_upper_half_increment contains a multi-precision integer, so after the
                    // addition we decompose the multi-precision integer into RNS components, and then multiply.
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain[mono_exponent], temp);
                    context_data.rns_tool()->base_q()->decompose(temp, pool);
                    negacyclic_multiply_poly_mono_coeffmod(
                        encrypted, encrypted_size, temp, mono_exponent, coeff_modulus, encrypted, pool);
                }
                else
                {
                    // Every coeff_modulus prime is larger than plain_modulus, so there is no need to adjust the
                    // monomial. Instead, just do an RNS multiplication.
                    negacyclic_multiply_poly_mono_coeffmod(
                        encrypted, encrypted_size, plain[mono_exponent], mono_exponent, coeff_modulus, encrypted, pool);
                }
            }
            else
            {
                // The monomial represents a positive number, so no RNS multiplication is needed.
                negacyclic_multiply_poly_mono_coeffmod(
                    encrypted, encrypted_size, plain[mono_exponent], mono_exponent, coeff_modulus, encrypted, pool);
            }

            // Set the scale
            if (parms.scheme() == scheme_type::ckks)
            {
                encrypted.scale() *= plain.scale();
                if (!is_scale_within_bounds(encrypted.scale(), context_data))
                {
                    throw invalid_argument("scale out of bounds");
                }
            }

            return;
        }

        // Generic case: any plaintext polynomial
        // Allocate temporary space for an entire RNS polynomial
        auto temp(allocate_zero_poly(coeff_count, coeff_modulus_size, pool));

        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

            SIGMA_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count, [&](auto I) {
                auto plain_value = get<0>(I);
                if (plain_value >= plain_upper_half_threshold)
                {
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain_value, get<1>(I));
                }
                else
                {
                    *get<1>(I) = plain_value;
                }
            });

            context_data.rns_tool()->base_q()->decompose_array(temp_iter, coeff_count, pool);
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            RNSIter temp_iter(temp.get(), coeff_count);
            SIGMA_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size, [&](auto I) {
                SIGMA_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count, [&](auto J) {
                    get<0>(J) =
                        SIGMA_COND_SELECT(get<1>(J) >= plain_upper_half_threshold, get<1>(J) + get<1>(I), get<1>(J));
                });
            });
        }

        // Need to multiply each component in encrypted with temp; first step is to transform to NTT form
        RNSIter temp_iter(temp.get(), coeff_count);
        ntt_negacyclic_harvey(temp_iter, coeff_modulus_size, ntt_tables);

        SIGMA_ITERATE(iter(encrypted), encrypted_size, [&](auto I) {
            SIGMA_ITERATE(iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size, [&](auto J) {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(get<0>(J), get<3>(J));
                dyadic_product_coeffmod(get<0>(J), get<1>(J), coeff_count, get<2>(J), get<0>(J));
                inverse_ntt_negacyclic_harvey(get<0>(J), get<3>(J));
            });
        });

        // Set the scale
        if (parms.scheme() == scheme_type::ckks)
        {
            encrypted.scale() *= plain.scale();
            if (!is_scale_within_bounds(encrypted.scale(), context_data))
            {
                throw invalid_argument("scale out of bounds");
            }
        }
    }

    void Evaluator::multiply_plain_ntt(Ciphertext &encrypted_ntt, const Plaintext &plain_ntt) const
    {
        // Verify parameters.
        if (!plain_ntt.is_ntt_form())
        {
            throw invalid_argument("plain_ntt is not in NTT form");
        }
        if (encrypted_ntt.parms_id() != plain_ntt.parms_id())
        {
            throw invalid_argument("encrypted_ntt and plain_ntt parameter mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted_ntt.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        // Size check
        if (!product_fits_in(encrypted_ntt_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

//        std::cout << "Encode and encrypt start" << std::endl;
//        auto time_start = std::chrono::high_resolution_clock::now();


        ConstRNSIter plain_ntt_iter(plain_ntt.data(), coeff_count);
        SIGMA_ITERATE(iter(encrypted_ntt), encrypted_ntt_size, [&](auto I) {
            dyadic_product_coeffmod(I, plain_ntt_iter, coeff_modulus_size, coeff_modulus, I);
        });
        // TODO: support multi modulus coeff_modulus
//        kernel_util::dyadic_product_coeffmod_inplace(
//                encrypted_ntt.data(), plain_ntt.data(),
//                coeff_count, encrypted_ntt_size, coeff_modulus_size, coeff_modulus[0]);

//        auto time_end = std::chrono::high_resolution_clock::now();
//        auto time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
//        std::cout << "Encode and encrypt end [" << time_diff.count() << " microseconds]" << std::endl;

        // Set the scale
        encrypted_ntt.scale() *= plain_ntt.scale();
        if (!is_scale_within_bounds(encrypted_ntt.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }


    __global__ void gTransformToNttInplace(
            uint64_t* plain,
            size_t plain_coeff_count,
            size_t coeff_count,
            const uint64_t* plain_upper_half_increment,
            uint64_t plain_upper_half_threshold,
            size_t coeff_modulus_size
    ) {
    size_t tid = blockDim.x * blockIdx.x + threadIdx.x;

    for(int i = 0; i < coeff_modulus_size; i++){//coeff_modulus_size*ceff_count
        size_t plain_index = (coeff_modulus_size - 1 - i) * coeff_count + tid;
        size_t increment_index = (coeff_modulus_size - 1 - i);
        plain[plain_index] = (plain[tid] >= plain_upper_half_threshold) ?
        (plain[tid] + plain_upper_half_increment[increment_index]) : plain[tid];

    }
}
    void Evaluator::transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for the current context");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain is already in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeff_count();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();


        /*for(int i=0;i<4096;i++){
            cout<<plain_upper_half_increment[i]<<" ";
        }*/
        uint64_t* d_plain_upper_half_increment=KernelProvider::malloc<uint64_t>(coeff_modulus_size );
        KernelProvider::copy(d_plain_upper_half_increment, plain_upper_half_increment, coeff_modulus_size);

        //auto ntt_tables = iter(context_data.small_ntt_tables());
        auto ntt_tables = context_data.device_small_ntt_tables();
        //auto ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Resize to fit the entire NTT transformed (ciphertext size) polynomial
        // Note that the new coefficients are automatically set to 0
        plain.resize(coeff_count * coeff_modulus_size);//a0 a1->a0 mod m0 a1 mod m0 a1 mod m1 a1 mod m1

        RNSIter plain_iter(plain.data(), coeff_count);//4096
        //auto plain_iter = plain.data();
        if (!context_data.qualifiers().using_fast_plain_lift)//没有使用
        {
            // Allocate temporary space for an entire RNS polynomial
            // Slight semantic misuse of RNSIter here, but this works well
            SIGMA_ALLOCATE_ZERO_GET_RNS_ITER(temp, coeff_modulus_size, coeff_count, pool);

            SIGMA_ITERATE(iter(plain.data(), temp), plain_coeff_count, [&](auto I) {
                auto plain_value = get<0>(I);
                if (plain_value >= plain_upper_half_threshold)
                {
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain_value, get<1>(I));
                }
                else
                {
                    *get<1>(I) = plain_value;
                }
            });

            context_data.rns_tool()->base_q()->decompose_array(temp, coeff_count, pool);

            // Copy data back to plain
            set_poly(temp, coeff_count, coeff_modulus_size, plain.data());
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.

            // Create a "reversed" helper iterator that iterates in the reverse order both plain RNS components and
            // the plain_upper_half_increment values.
            /*auto helper_iter = reverse_iter(plain_iter, plain_upper_half_increment);
            advance(helper_iter, -safe_cast<ptrdiff_t>(coeff_modulus_size - 1));

            SIGMA_ITERATE(helper_iter, coeff_modulus_size, [&](auto I) {
                SIGMA_ITERATE(iter(*plain_iter, get<0>(I)), plain_coeff_count, [&](auto J) {
                    get<1>(J) =
                        SIGMA_COND_SELECT(get<0>(J) >= plain_upper_half_threshold, get<0>(J) + get<1>(I), get<0>(J));
                });
            });*/

            uint64_t* d_temp=KernelProvider::malloc<uint64_t>(coeff_modulus_size * plain_coeff_count);
            KernelProvider::copy(d_temp, plain.data(), coeff_modulus_size * plain_coeff_count);
            //sigma::kernel_util::g_ntt_negacyclic_harvey(d_temp, 4096 ,tables);
/*            KernelProvider::retrieve(operand.ptr(), d_temp, 4096);
            KernelProvider::free(d_temp);*/
            // Finally maybe we need to red
            size_t blocknumber = ceil(plain_coeff_count / 256.0);
            gTransformToNttInplace <<<blocknumber, 256>>>(
                    d_temp, plain_coeff_count, coeff_count, d_plain_upper_half_increment,
                    plain_upper_half_threshold, coeff_modulus_size);
            KernelProvider::retrieve(plain.data(), d_temp, coeff_modulus_size * plain_coeff_count);
            KernelProvider::free(d_temp);
        }

        // Transform to NTT domain
              //ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables);// 2
        ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables);// 2
        //sigma::kernel_util::g_ntt_negacyclic_harvey((uint64_t*)plain_iter, parms.poly_modulus_degree(), *ntt_tables);
        plain.parms_id() = parms_id;
    }

    void Evaluator::transform_to_ntt_inplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted is already in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        auto ntt_tables = iter(context_data.device_small_ntt_tables());

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial to NTT domain
        ntt_negacyclic_harvey(encrypted, encrypted_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted.is_ntt_form() = true;
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::transform_from_ntt_inplace(Ciphertext &encrypted_ntt) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted_ntt, context_) || !is_buffer_valid(encrypted_ntt))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted_ntt.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted_ntt is not valid for encryption parameters");
        }
        if (!encrypted_ntt.is_ntt_form())
        {
            throw invalid_argument("encrypted_ntt is not in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        auto ntt_tables = iter(context_data.small_ntt_tables());

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial from NTT domain
        inverse_ntt_negacyclic_harvey(encrypted_ntt, encrypted_ntt_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted_ntt.is_ntt_form() = false;
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted_ntt.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::sealpir_transform_from_ntt_inplace(Ciphertext &encrypted_ntt)
    {
        auto context_data_ptr = context_.get_context_data(encrypted_ntt.parms_id());
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        auto ntt_tables = iter(context_data.device_small_ntt_tables());
        size_t coeff_power = get_power_of_two(coeff_count);
        // Transform each polynomial from NTT domain

        //#pragma unroll
        for(int i = 0; i < encrypted_ntt_size; i++) {
            for (int j = 0; j < coeff_modulus_size; j++) {
                kernel_util::d_inverse_ntt_negacyclic_harvey(
                        encrypted_ntt.device_data() + i * coeff_count * coeff_modulus_size + j * coeff_count,
                        1,1,coeff_power,ntt_tables[j]);

            }

        }


        encrypted_ntt.retrieve_to_host();
        // Finally change the is_ntt_transformed flag
        encrypted_ntt.is_ntt_form() = false;

        //encrypted_ntt.retrieve_to_host();
    }

    void Evaluator::apply_galois_inplace(
        Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Don't validate all of galois_keys but just check the parms_id.
        if (galois_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();
        // Use key_context_data where permutation tables exist since previous runs.
        auto galois_tool = context_.key_context_data()->galois_tool();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Check if Galois key is generated or not.
        if (!galois_keys.has_key(galois_elt))
        {
            throw invalid_argument("Galois key not present");
        }

        uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));

        // Verify parameters
        if (!(galois_elt & 1) || unsigned_geq(galois_elt, m))
        {
            throw invalid_argument("Galois element is not valid");
        }
        if (encrypted_size > 2)
        {
            throw invalid_argument("encrypted size must be 2");
        }

        SIGMA_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);

        // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
        // BEGIN: Apply Galois for each ciphertext
        // Execution order is sensitive, since apply_galois is not inplace!
        if (parms.scheme() == scheme_type::bfv)
        {
            // !!! DO NOT CHANGE EXECUTION ORDER!!!

            // First transform encrypted.data(0)
            auto encrypted_iter = iter(encrypted);
            uint64_t* d_temp=KernelProvider::malloc<uint64_t>(coeff_count * coeff_modulus_size);
            KernelProvider::copy(d_temp, (uint64_t*)encrypted_iter[0], coeff_count * coeff_modulus_size);
            uint64_t* d_result=KernelProvider::malloc<uint64_t>(coeff_count * coeff_modulus_size);

            galois_tool->cu_apply_galois(d_temp, coeff_modulus_size, galois_elt, coeff_modulus, d_result);

            KernelProvider::retrieve((uint64_t*)temp, d_result, coeff_count * coeff_modulus_size);
            KernelProvider::free(d_temp);

            // Copy result to encrypted.data(0)
            set_poly(temp, coeff_count, coeff_modulus_size, encrypted.data(0));

            // Next transform encrypted.data(1)
            galois_tool->apply_galois(encrypted_iter[1], coeff_modulus_size, galois_elt, coeff_modulus, temp);
        }
        else if (parms.scheme() == scheme_type::ckks || parms.scheme() == scheme_type::bgv)
        {
            // !!! DO NOT CHANGE EXECUTION ORDER!!!

            // First transform encrypted.data(0)
            auto encrypted_iter = iter(encrypted);
            galois_tool->apply_galois_ntt(encrypted_iter[0], coeff_modulus_size, galois_elt, temp);

            // Copy result to encrypted.data(0)
            set_poly(temp, coeff_count, coeff_modulus_size, encrypted.data(0));

            // Next transform encrypted.data(1)
            galois_tool->apply_galois_ntt(encrypted_iter[1], coeff_modulus_size, galois_elt, temp);
        }
        else
        {
            throw logic_error("scheme not implemented");
        }

        // Wipe encrypted.data(1)
        set_zero_poly(coeff_count, coeff_modulus_size, encrypted.data(1));

        // END: Apply Galois for each ciphertext
        // REORDERING IS SAFE NOW

        // Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
        switch_key_inplace(
            encrypted, temp, static_cast<const KSwitchKeys &>(galois_keys), GaloisKeys::get_index(galois_elt), pool);
#ifdef SIGMA_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
//        if (encrypted.is_transparent())
//        {
//            throw logic_error("result ciphertext is transparent");
//        }
#endif
    }

    void Evaluator::rotate_internal(
        Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
    {
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_data_ptr->qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }
        if (galois_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }

        // Is there anything to do?
        if (steps == 0)
        {
            return;
        }

        size_t coeff_count = context_data_ptr->parms().poly_modulus_degree();
        auto galois_tool = context_data_ptr->galois_tool();

        // Check if Galois key is generated or not.
        if (galois_keys.has_key(galois_tool->get_elt_from_step(steps)))
        {
            // Perform rotation and key switching
            apply_galois_inplace(encrypted, galois_tool->get_elt_from_step(steps), galois_keys, move(pool));
        }
        else
        {
            // Convert the steps to NAF: guarantees using smallest HW
            vector<int> naf_steps = naf(steps);

            // If naf_steps contains only one element, then this is a power-of-two
            // rotation and we would have expected not to get to this part of the
            // if-statement.
            if (naf_steps.size() == 1)
            {
                throw invalid_argument("Galois key not present");
            }

            SIGMA_ITERATE(naf_steps.cbegin(), naf_steps.size(), [&](auto step) {
                // We might have a NAF-term of size coeff_count / 2; this corresponds
                // to no rotation so we skip it. Otherwise call rotate_internal.
                if (safe_cast<size_t>(abs(step)) != (coeff_count >> 1))
                {
                    // Apply rotation for this step
                    this->rotate_internal(encrypted, step, galois_keys, pool);
                }
            });
        }
    }

    void Evaluator::switch_key_inplace(
        Ciphertext &encrypted, ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
        MemoryPoolHandle pool) const
    {
        auto parms_id = encrypted.parms_id();
        auto &context_data = *context_.get_context_data(parms_id);
        auto &parms = context_data.parms();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        auto scheme = parms.scheme();

        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_iter)
        {
            throw invalid_argument("target_iter");
        }
        if (!context_.using_keyswitching())
        {
            throw logic_error("keyswitching is not supported by the context");
        }

        // Don't validate all of kswitch_keys but just check the parms_id.
        if (kswitch_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("parameter mismatch");
        }

        if (kswitch_keys_index >= kswitch_keys.data().size())
        {
            throw out_of_range("kswitch_keys_index");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (scheme == scheme_type::bfv && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (scheme == scheme_type::ckks && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (scheme == scheme_type::bgv && !encrypted.is_ntt_form())
        {
            throw invalid_argument("BGV encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        size_t coeff_count = parms.poly_modulus_degree();//4096
        size_t decomp_modulus_size = parms.coeff_modulus().size();//2
        auto &key_modulus = key_parms.coeff_modulus();//Modulus类型
        size_t key_modulus_size = key_modulus.size();//3
        size_t rns_modulus_size = decomp_modulus_size + 1;//3
        auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
        auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

        // Size check
        if (!product_fits_in(coeff_count, rns_modulus_size, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }

        // Prepare input
        auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector[0].data().size();

        // Check only the used component in KSwitchKeys.
        for (auto &each_key : key_vector)
        {
            if (!is_metadata_valid_for(each_key, context_) || !is_buffer_valid(each_key))
            {
                throw invalid_argument("kswitch_keys is not valid for encryption parameters");
            }
        }

        // Create a copy of target_iter
        SIGMA_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
        set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

        // In CKKS or BGV, t_target is in NTT form; switch back to normal form
        if (scheme == scheme_type::ckks || scheme == scheme_type::bgv)
        {
            inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);
        }

        // Temporary result
        auto t_poly_prod(allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

        SIGMA_ITERATE(iter(size_t(0)), rns_modulus_size, [&](auto I) {//这里不执行
            size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            size_t lazy_reduction_summand_bound = size_t(SIGMA_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            auto t_poly_lazy(allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

            // Multiply with keys and perform lazy reduction on product's coefficients
            SIGMA_ITERATE(iter(size_t(0)), decomp_modulus_size, [&](auto J) {
                SIGMA_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                ConstCoeffIter t_operand;

                // RNS-NTT form exists in input
                if ((scheme == scheme_type::ckks || scheme == scheme_type::bgv) && (I == J))
                {
                    t_operand = target_iter[J];
                }
                // Perform RNS-NTT conversion
                else
                {
                    // No need to perform RNS conversion (modular reduction)
                    if (key_modulus[J] <= key_modulus[key_index])
                    {
                        set_uint(t_target[J], coeff_count, t_ntt);
                    }
                    // Perform RNS conversion (modular reduction)
                    else
                    {
                        modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index], t_ntt);
                    }
                    // NTT conversion lazy outputs in [0, 4q)
                    ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                    t_operand = t_ntt;
                }

                // Multiply with keys and modular accumulate products in a lazy fashion
                SIGMA_ITERATE(iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                    if (!lazy_reduction_counter)
                    {
                        SIGMA_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);

                            // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = barrett_reduce_128(qword, key_modulus[key_index]);
                            get<2>(L)[1] = 0;
                        });
                    }
                    else
                    {
                        // Same as above but no reduction
                        SIGMA_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = qword[0];
                            get<2>(L)[1] = qword[1];
                        });
                    }
                });

                if (!--lazy_reduction_counter)
                {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }
            });

            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

            // Final modular reduction
            SIGMA_ITERATE(iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
                if (lazy_reduction_counter == lazy_reduction_summand_bound)
                {
                    SIGMA_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        get<1>(L) = static_cast<uint64_t>(*get<0>(L));
                    });
                }
                else
                {
                    // Same as above except need to still do reduction
                    SIGMA_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        get<1>(L) = barrett_reduce_128(get<0>(L).ptr(), key_modulus[key_index]);
                    });
                }
            });
        });
        // Accumulated products are now stored in t_poly_prod

        // Perform modulus switching with scaling 这里执行
        PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
        SIGMA_ITERATE(iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
            if (scheme == scheme_type::bgv)
            {
                const Modulus &plain_modulus = parms.plain_modulus();
                // qk is the special prime
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_inv_qp = context_.key_context_data()->rns_tool()->inv_q_last_mod_t();

                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey(t_last, key_ntt_tables[key_modulus_size - 1]);

                SIGMA_ALLOCATE_ZERO_GET_COEFF_ITER(k, coeff_count, pool);
                modulo_poly_coeffs(t_last, coeff_count, plain_modulus, k);
                negate_poly_coeffmod(k, coeff_count, plain_modulus, k);
                if (qk_inv_qp != 1)
                {
                    multiply_poly_scalar_coeffmod(k, coeff_count, qk_inv_qp, plain_modulus, k);
                }

                SIGMA_ALLOCATE_ZERO_GET_COEFF_ITER(delta, coeff_count, pool);
                SIGMA_ALLOCATE_ZERO_GET_COEFF_ITER(c_mod_qi, coeff_count, pool);
                SIGMA_ITERATE(iter(I, key_modulus, modswitch_factors, key_ntt_tables), decomp_modulus_size, [&](auto J) {
                    // delta = k mod q_i
                    modulo_poly_coeffs(k, coeff_count, get<1>(J), delta);
                    // delta = k * q_k mod q_i
                    multiply_poly_scalar_coeffmod(delta, coeff_count, qk, get<1>(J), delta);

                    // c mod q_i
                    modulo_poly_coeffs(t_last, coeff_count, get<1>(J), c_mod_qi);
                    // delta = c + k * q_k mod q_i
                    // c_{i} = c_{i} - delta mod q_i
                    SIGMA_ITERATE(iter(delta, c_mod_qi), coeff_count, [&](auto K) {
                        get<0>(K) = add_uint_mod(get<0>(K), get<1>(K), get<1>(J));
                    });
                    ntt_negacyclic_harvey(delta, get<3>(J));
                    SIGMA_ITERATE(iter(delta, get<0, 1>(J)), coeff_count, [&](auto K) {
                        get<1>(K) = sub_uint_mod(get<1>(K), get<0>(K), get<1>(J));
                    });

                    multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<2>(J), get<1>(J), get<0, 1>(J));

                    add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
                });
            }
            else
            {
                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

                // Add (p-1)/2 to change from flooring to rounding.
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_half = qk >> 1;
                SIGMA_ITERATE(t_last, coeff_count, [&](auto &J) {
                    J = barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]);
                });

                SIGMA_ITERATE(iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size, [&](auto J) {
                    SIGMA_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                    // (ct mod 4qk) mod qi
                    uint64_t qi = get<1>(J).value();
                    if (qk > qi)
                    {
                        // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                        modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                    }
                    else
                    {
                        set_uint(t_last, coeff_count, t_ntt);
                    }

                    // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                    uint64_t fix = qi - barrett_reduce_64(qk_half, get<1>(J));
                    SIGMA_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                    uint64_t qi_lazy = qi << 1; // some multiples of qi
                    if (scheme == scheme_type::ckks)
                    {
                        // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                        ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if SIGMA_USER_MOD_BIT_COUNT_MAX > 60
                        // Reduce from [0, 4qi) to [0, 2qi)
                        SIGMA_ITERATE(
                            t_ntt, coeff_count, [&](auto &K) { K -= SIGMA_COND_SELECT(K >= qi_lazy, qi_lazy, 0); });
#else
                        // Since SIGMA uses at most 60bit moduli, 8*qi < 2^63.
                        qi_lazy = qi << 2;
#endif
                    }
                    else if (scheme == scheme_type::bfv)
                    {
                        inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));
                    }

                    // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                    SIGMA_ITERATE(
                        iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                    // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                    multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J), get<1>(J), get<0, 1>(J));
                    add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
                });
            }
        });
    }

    __global__ void printfdebug(uint64_t* plaintext){
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;//线程索引
        printf("%d ",plaintext[tid]);
    }

    void Evaluator::preprocess_transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id)
    {
        // Extract encryption parameters.
        auto context_data_ptr = context_.get_context_data(parms_id);

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeff_count();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();

        uint64_t* d_plain_upper_half_increment = KernelProvider::malloc<uint64_t>(coeff_modulus_size);
        KernelProvider::copy(d_plain_upper_half_increment, plain_upper_half_increment, coeff_modulus_size);

        auto ntt_tables = context_data.device_small_ntt_tables();//一个指针

        plain.resize(coeff_count * coeff_modulus_size);//a0 a1->a0 mod m0 a1 mod m0 a1 mod m1 a1 mod m1
        KernelProvider::retrieve(plain.data(), plain.device_data(), coeff_count);

        plain.copy_to_device();

        RNSIter plain_iter(plain.device_data(), coeff_count);//4096

        size_t blocknumber = ceil(plain_coeff_count / 256.0);
        gTransformToNttInplace <<<blocknumber, 256>>>(
                plain.device_data(), plain_coeff_count, coeff_count, d_plain_upper_half_increment,
                plain_upper_half_threshold, coeff_modulus_size);


        for(int i = 0; i < coeff_modulus_size; i++){
            g_ntt_negacyclic_harvey(plain.device_data() + i * coeff_count, coeff_count, ntt_tables[i]);
        }

    }

    void Evaluator::sealpir_transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id)
    {
        // Verify parameters.


        auto context_data_ptr = context_.get_context_data(parms_id);

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeff_count();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();


        uint64_t* d_plain_upper_half_increment=KernelProvider::malloc<uint64_t>(coeff_modulus_size);
        KernelProvider::copy(d_plain_upper_half_increment, plain_upper_half_increment, coeff_modulus_size);

        auto ntt_tables = context_data.device_small_ntt_tables();

        plain.resize(coeff_count * coeff_modulus_size);//a0 a1->a0 mod m0 a1 mod m0 a1 mod m1 a1 mod m1
        KernelProvider::retrieve(plain.data(),plain.device_data(),coeff_count);

        plain.copy_to_device();


            // Finally maybe we need to red
        size_t blocknumber = ceil(plain_coeff_count / 1024.0);
        gTransformToNttInplace <<<blocknumber, 1024>>>(
                plain.device_data(), plain_coeff_count, coeff_count, d_plain_upper_half_increment,
                plain_upper_half_threshold, coeff_modulus_size);

        #pragma unroll
        for(int i = 0; i < coeff_modulus_size; i++){
            g_ntt_negacyclic_harvey(plain.device_data() + i * coeff_count, coeff_count, ntt_tables[i]);
        }

        plain.parms_id() = parms_id;
    }

    void Evaluator::sealpir_transform_to_ntt_inplace(Ciphertext &encrypted)
    {
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        auto ntt_tables = iter(context_data.device_small_ntt_tables());

        // Transform each polynomial to NTT domain
        for(int i = 0; i < encrypted_size; i++) {
            for(int j = 0; j < coeff_modulus_size; j++) {
                g_ntt_negacyclic_harvey((uint64_t *) encrypted.device_data() + i * coeff_count * coeff_modulus_size + j * coeff_count,
                                        coeff_count, ntt_tables[j]);
            }
        }

        // Finally change the is_ntt_transformed flag
        encrypted.is_ntt_form() = true;
    }

    __global__ void g_set_uint(uint64_t* operand, uint64_t value){

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        if(tid == 0){
            operand[tid] = value;
        }
        else{
            operand[tid] = 0;
        }
    }

    __global__ void printfdebug(uint64_t data){
        printf("%d ",data);
    }
    __global__ void g_switch_key_inplace_A(
            uint64_t* t_poly_lazy,
            size_t coeff_count,
            size_t key_component_count,
            const uint64_t* key_vector_j,
            size_t key_poly_coeff_size,
            const uint64_t* t_operand,
            size_t key_index,
            const Modulus* key_modulus
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        for(int k = 0; k < key_component_count; k++){
            uint64_t qword[2] {0, 0};
            const uint64_t* key_vector_j_k = key_vector_j + k * key_poly_coeff_size;//key_index 模的索引
            kernel_util::d_multiply_uint64(t_operand[tid], key_vector_j_k[key_index * coeff_count + tid], qword);
            auto accumulator_l = t_poly_lazy + k * coeff_count * 2 + 2 * tid;
            kernel_util::d_add_uint128(qword, accumulator_l, qword);
            accumulator_l[0] = qword[0];
            accumulator_l[1] = qword[1];
        }//(-as + e) * a(x^p) mod m1, a * a(x^p) mod m1 key_component_count * coeff_count * 2

    }

    __global__ void g_switch_key_inplace_B(
            //(-a1s + e + m3s(x^p)) * (a(x^p) mod m1) + (-a2s + e) * (a(x^p) mod m2) mod m1
            //a1 * (a(x^p) mod m1) + a2 * (a(x^p) mod m2) mod m1
            const uint64_t* t_poly_lazy,
            size_t coeff_count,
            size_t key_component_count,
            size_t rns_modulus_size,
            uint64_t* t_poly_prod_iter,
            size_t key_index,
            const Modulus* key_modulus
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        for(int k = 0; k < key_component_count; k++){
            const uint64_t* accumulator = t_poly_lazy + k * coeff_count * 2;
            t_poly_prod_iter[k * coeff_count * rns_modulus_size + tid] =
                    kernel_util::d_barrett_reduce_128(accumulator + tid * 2, key_modulus[key_index]);
        }
    }

    __global__ void g_switch_key_inplace_C(
            uint64_t* t_last,
            size_t coeff_count,
            const Modulus* qk,
            const Modulus* key_modulus,
            uint64_t qk_half,
            size_t decomp_modulus_size,
            uint64_t* t_ntt // t_ntt should be at least coeff_count * decomp_modulus_size
    ) {

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        t_last[tid] = kernel_util::d_barrett_reduce_64(t_last[tid] + qk_half, *qk);

        for(int j = 0; j < decomp_modulus_size; j++){
            const Modulus& qi = key_modulus[j];
            if (qk->value() > qi.value()) {
                t_ntt[j * coeff_count + tid] = kernel_util::d_barrett_reduce_64(t_last[tid], qi);
            } else {
                t_ntt[j * coeff_count + tid] = t_last[tid];
            }
            uint64_t fix = qi.value() - kernel_util::d_barrett_reduce_64(qk_half, key_modulus[j]);
            t_ntt[j * coeff_count + tid] += fix;
        }
    }

    __global__ void g_switch_key_inplace_D(
            uint64_t* t_poly_prod_i,
            const uint64_t* t_ntt,
            size_t coeff_count,
            uint64_t* encrypted_i,
            bool is_ckks,
            size_t decomp_modulus_size,
            const Modulus* key_modulus,
            const MultiplyUIntModOperand* modswitch_factors
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        for(int j = 0; j < decomp_modulus_size; j++){
            //printf("%d ",key_modulus[j].value());
            uint64_t& dest = t_poly_prod_i[j * coeff_count + tid];
            uint64_t qi = key_modulus[j].value();
            dest += ((is_ckks) ? (qi << 2) : (qi << 1)) - t_ntt[j * coeff_count + tid];
            dest = kernel_util::d_multiply_uint_mod(dest, modswitch_factors[j], key_modulus[j]);
            //printf("%d ", encrypted_i[j * coeff_count + tid]);
            encrypted_i[j * coeff_count + tid] = kernel_util::d_add_uint_mod(
                    encrypted_i[j * coeff_count + tid], dest, key_modulus[j]
            );
        }
    }

    __global__ void printfmodulus(const Modulus* modulus){

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        uint64_t modulus_value = modulus[tid].value();
        //printf("%d ", modulus_value);
    }

    void Evaluator::sealpir_switch_key_inplace(
            Ciphertext &encrypted, uint64_t* target_iter, const KSwitchKeys &kswitch_keys, size_t kswitch_keys_index,
            MemoryPoolHandle pool) const//encrypted 两个密文 target_iter coeff_count * coeff_modulus_size
    {//bfv不为NTT模式 target_iter为host端
        auto parms_id = encrypted.parms_id();
        auto &context_data = *context_.get_context_data(parms_id);
        auto &parms = context_data.parms();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        auto scheme = parms.scheme();

        // Extract encryption parameters.
        size_t coeff_count = parms.poly_modulus_degree();//4096
        size_t coeff_power = get_power_of_two(coeff_count);
        size_t decomp_modulus_size = parms.coeff_modulus().size();//2
        auto &key_modulus = key_parms.coeff_modulus();//Modulus类型
        auto &key_modulus_to_device = key_parms.device_coeff_modulus();//Modulus类型
        size_t key_modulus_size = key_modulus.size();//3
        size_t rns_modulus_size = decomp_modulus_size + 1;//3
        auto key_ntt_tables = key_context_data.device_small_ntt_tables();
        auto modswitch_factors = key_context_data.rns_tool()->inv_q_last_mod_q();

        MultiplyUIntModOperand *d_modswitch_factor = KernelProvider::malloc<MultiplyUIntModOperand>(
                decomp_modulus_size);
        KernelProvider::copy(d_modswitch_factor, modswitch_factors, decomp_modulus_size);


        auto &key_vector_to_host = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector_to_host[0].data().size();//一个密文长度 c0 c1组成

        // Create a copy of target_iter
        //SIGMA_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);//分配一个RNS，可当unit64_t使用
        //set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);//target_iter复制给到t_target
        uint64_t *t_target = KernelProvider::malloc<uint64_t>(coeff_count * decomp_modulus_size);
        //uint64_t* t_target = (uint64_t*)malloc(coeff_count * decomp_modulus_size)
        KernelProvider::copyOnDevice(t_target, (uint64_t *)target_iter, decomp_modulus_size * coeff_count);//encrypted[1]处理的值

        //printfdebug<<<1,100>>>(key_modulus_to_device.get()[0].value());
        // Temporary result 分配一个大小key_component_count*coeff_count*rns_modulus_size大小，元素全为0

        uint64_t *t_poly_prod = KernelProvider::malloc<uint64_t>(key_component_count * coeff_count * rns_modulus_size);
        KernelProvider::memsetZero(t_poly_prod, key_component_count * coeff_count * rns_modulus_size);
        //密文c0扩展成了rns_modulus_size （不管c0一开始模了几个模数）
        for (int i = 0; i < rns_modulus_size; i++) {
            size_t key_index = (i == decomp_modulus_size ? key_modulus_size - 1 : i);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            size_t lazy_reduction_summand_bound = size_t(SIGMA_MULTIPLY_ACCUMULATE_USER_MOD_MAX);//256
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;//256

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            uint64_t *t_poly_lazy = KernelProvider::malloc<uint64_t>(key_component_count * coeff_count * 2);
            KernelProvider::memsetZero(t_poly_lazy, key_component_count * coeff_count * 2);//乘法位数加倍

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            //以多项式为单位的步长 设备端应该可以使用
            // Multiply with keys and perform lazy reduction on product's coefficients
            uint64_t *t_ntt = KernelProvider::malloc<uint64_t>(coeff_count);
            for (int j = 0; j < decomp_modulus_size; j++) {//取出a(x^p)
                uint64_t* t_operand;
                // No need to perform RNS conversion (modular reduction)
                if (key_modulus[j] <= key_modulus[key_index]) {//target a(x^p) mod m1 mod m2
                    KernelProvider::copyOnDevice(t_ntt, t_target + j * coeff_count, coeff_count);
                }
                    // Perform RNS conversion (modular reduction)
                else {
                    kernel_util::d_modulo_poly_coeffs(t_target + j * coeff_count, coeff_count,
                                                      key_modulus_to_device.get()[key_index], t_ntt);//约减已有加速
                }
                // NTT conversion lazy outputs in [0, 4q)
                kernel_util::g_ntt_negacyclic_harvey(t_ntt, coeff_count, key_ntt_tables[key_index]);
                //ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                t_operand = t_ntt;//uint64_t* a(x^p)

                size_t key_vector_poly_coeff_size = key_vector_to_host[j].data().
                        poly_modulus_degree() * key_vector_to_host[j].data().coeff_modulus_size();
                // Multiply with keys and modular accumulate products in a lazy fashion key_component_count 2

                uint64_t *key_vector_j = KernelProvider::malloc<uint64_t>(
                        key_vector_poly_coeff_size * key_component_count);//整个key密文

                //auto tempkeys = key_vector_to_host[j].data();//pk ciphertext
                //auto tempkeys = key_vector_to_host[j].data().data();//uint64_t*
                KernelProvider::copy(key_vector_j, key_vector_to_host[j].data().data(),
                                     key_vector_poly_coeff_size * key_component_count);//一个完整key c0 c1 a(x^p)一个coeff_count
                //(-as + e + m3s(x^p)) mod m1 (-as + e) mod m2 (-as + e) mod m3 a mod m1 a mod m2 a mod m3

                //(-a1s + e + m3s(x^p)) * a_(x^p) mod m1 (-a1s + e) mod m2 (-a1s + e) mod m3 a1 * a_(x^p) mod m1 a1 mod m2 a1 mod m3
                //(-a2s + e) mod m1 (-a2s + e + m3s(x^p)) * a_(x^p) mod m2 (-a2s + e) mod m3 a2 mod m1 a2 * a_(x^p) mod m2 a mod m3

                //destination一开始赋值两个一样 (-a1s + e + m3s(x^p)) mod m1 (-a1s + e) mod m2 (-a1s + e) mod m3 a1 mod m1 a1 mod m2 a1 mod m3
                //destination一开始赋值两个一样 (-a2s + e) mod m1 (-a2s + e + m3s(x^p)) mod m2 (-a2s + e) mod m3 a2 mod m1 a2 mod m2 a2 mod m3
                //printfdebug<<<24, 1024>>>(key_vector_j);
                size_t blocknum = ceil(coeff_count / 1024.0);
                g_switch_key_inplace_A<<<blocknum, 1024>>>(t_poly_lazy, coeff_count, key_component_count,
                                                           key_vector_j, key_vector_poly_coeff_size,
                                                           t_operand, key_index,//t_operand = a(x^p) mod m1
                                                           key_modulus_to_device.get());//keymodulus注意
                                                            //a(x^p)一个coeff_count
                //(-a1s + e + m3s(x^p)) mod m1 * (a(x^p) mod m1),                  a1 mod m1 * (a(x^p) mod m1)) loop1
                //(-a2s + e) mod m1 * (a(x^p) mod m2),                             a2 mod m1 * (a(x^p) mod m2)) loop2                  LOOP1

                //(-a1s + e) mod m2 * (a(x^p) mod m1),                             a1 mod m2 * (a(x^p) mod m1)) loop1
                //(-a2s + e + m3s(x^p)) mod m2 * (a(x^p) mod m2),                  a2 mod m2 * (a(x^p) mod m2)) loop2                  LOOP2

                //(-a1s + e) mod m2 * (a(x^p) mod m1),                             a1 mod m2 * (a(x^p) mod m1)) loop1
                //(-a2s + e + m3s(x^p)) mod m2 * (a(x^p) mod m2),                  a2 mod m2 * (a(x^p) mod m2)) loop2                  LOOP3

                //(-a1s + e * a(x^p) mod m2, a1 * a(x^p) mod m2)      (-a2s + e + m3s(x^p)) * a(x^p) mod m2, a2 * a(x^p)) mod m2)
                // key_component_count * coeff_count * 2
                if (!--lazy_reduction_counter) {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }
            }//(-a1s + e + m3s(x^p)) * (a(x^p) mod m1) + (-a1s + e) * (a(x^p) mod m1) mod m1 = m3s(x^p)(a(x^p)) mod m1

            //(-a1s + e + m3s(x^p)) * (a(x^p) mod m1) + (-a2s + e) * (a(x^p) mod m2) mod m1
            //a1 * (a(x^p) mod m1) + a2 * (a(x^p) mod m2) mod m1
            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            auto t_poly_prod_iter = t_poly_prod + i * coeff_count;

            size_t blocknum = ceil(coeff_count / 1024.0);//约简
            g_switch_key_inplace_B<<<blocknum, 1024>>>(t_poly_lazy, coeff_count, key_component_count,
                                                       rns_modulus_size, t_poly_prod_iter, key_index,
                                                       key_modulus_to_device.get());

        }


        for (int i = 0; i < key_component_count; i++) {

            // Lazy reduction; this needs to be then reduced mod qi
            auto t_last = t_poly_prod + coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;

            //-(a1 + a2)a(x^p)s + e + m3s(x^p)a(x^p),            (a1 + a2)a(x^p)          mod m1
            uint64_t *t_ntt = KernelProvider::malloc<uint64_t>(decomp_modulus_size * coeff_count);
            KernelProvider::memsetZero(t_ntt, decomp_modulus_size * coeff_count);

            //CoeffIter t_last(t_poly_prod_iter[i][decomp_modulus_size]);
            kernel_util::d_inverse_ntt_negacyclic_harvey(t_last, 1, 1, coeff_power, key_ntt_tables[key_modulus_size - 1]);;

            size_t blocknum = ceil(coeff_count / 1024.0);
            g_switch_key_inplace_C<<<blocknum, 1024>>>(t_last, coeff_count,
                                                       key_modulus_to_device.get() + (key_modulus_size - 1),
                                                       key_modulus_to_device.get(),
                                                       key_modulus[key_modulus_size - 1].value() >> 1,
                                                       decomp_modulus_size,
                                                       t_ntt);
            CHECK(cudaGetLastError());


            for (int t = 0; t < decomp_modulus_size; t++) {
                kernel_util::d_inverse_ntt_negacyclic_harvey_lazy(//逆ntt
                        t_poly_prod + i * coeff_count * rns_modulus_size + t * coeff_count,
                        1, 1, coeff_power,
                        key_ntt_tables[t]
                );
            }
            //printfdebug<<<1,1024>>>(t_poly_prod);
            g_switch_key_inplace_D<<<blocknum, 1024>>>(t_poly_prod + i * coeff_count * rns_modulus_size,
                                                       t_ntt, coeff_count, encrypted.device_data() + i * coeff_count * decomp_modulus_size,
                                                       scheme == scheme_type::ckks, decomp_modulus_size,
                                                       key_modulus_to_device.get(),
                                                       d_modswitch_factor
            );
        }
        CHECK(cudaGetLastError());

    }

void Evaluator::sealpir_apply_galois_inplace(
        Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys,
        MemoryPoolHandle pool) const
{//encrypted存在device

    auto &context_data = *context_.get_context_data(encrypted.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t encrypted_size = encrypted.size();
    // Use key_context_data where permutation tables exist since previous runs.
    auto galois_tool = context_.key_context_data()->galois_tool();

    uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));

    // Verify parameters
    SIGMA_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);
    //uint64_t* temp = (uint64_t*)malloc(coeff_count * coeff_modulus_size);

    // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
    // BEGIN: Apply Galois for each ciphertext
    // Execution order is sensitive, since apply_galois is not inplace!
    // !!! DO NOT CHANGE EXECUTION ORDER!!!

    // First transform encrypted.data(0)
    auto encrypted_iter = iter(encrypted);

    uint64_t* d_result=KernelProvider::malloc<uint64_t>(coeff_count * coeff_modulus_size);

    galois_tool->cu_apply_galois(encrypted.device_data(), coeff_modulus_size, galois_elt, coeff_modulus, d_result);


    // Copy result to encrypted.data(0)
    KernelProvider::copyOnDevice(encrypted.device_data(), d_result, coeff_count * coeff_modulus_size);
    //set_poly(temp, coeff_count, coeff_modulus_size, encrypted.data(0));

    // Next transform encrypted.data(1)
    galois_tool->cu_apply_galois(encrypted.device_data() + coeff_modulus_size * coeff_count, coeff_modulus_size, galois_elt, coeff_modulus, d_result);

    // Wipe encrypted.data(1)
    KernelProvider::memsetZero(encrypted.device_data() + coeff_modulus_size * coeff_count, coeff_count * coeff_modulus_size);

    // END: Apply Galois for each ciphertext
    // REORDERING IS SAFE NOW

    // Calculate (temp * galois_key[0], temp * galois_key[1]) + (ct[0], 0)
    sealpir_switch_key_inplace(
            encrypted, d_result, static_cast<const KSwitchKeys &>(galois_keys), GaloisKeys::get_index(galois_elt), pool);

    }

    void Evaluator::cu_add(Ciphertext &encrypted1, const Ciphertext &encrypted2, Ciphertext &result) {
        // Verify parameters.
//        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1)) {
//            throw invalid_argument("encrypted1 is not valid for encryption parameters");
//        }
//        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2)) {
//            throw invalid_argument("encrypted2 is not valid for encryption parameters");
//        }
//        if (encrypted1.parms_id() != encrypted2.parms_id()) {
//            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
//        }
//        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form()) {
//            throw invalid_argument("NTT form mismatch");
//        }
//        if (!are_same_scale(encrypted1, encrypted2)) {
//            throw invalid_argument("scale mismatch");
//        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();

        result = encrypted1;
        result.copy_to_device();

        for(int i = 0; i < encrypted1.size(); i++) {
            for (int j = 0; j < coeff_modulus_size; j++) {
                kernel_util::add_poly_coeffmod(
                        encrypted1.device_data() + i * coeff_count * coeff_modulus_size + j * coeff_count,
                        encrypted2.device_data() + i * coeff_count * coeff_modulus_size + j * coeff_count,
                        1, 1, coeff_count, coeff_modulus[j].value(),
                        result.device_data() + i * coeff_count * coeff_modulus_size + j * coeff_count);
            }
        }
        result.retrieve_to_host();
    }
} // namespace sigma

