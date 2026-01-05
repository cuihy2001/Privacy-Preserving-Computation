// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "context.h"
#include "plaintext.cuh"
#include "util/common.h"
#include "util/croots.h"
#include "util/defines.h"
#include "util/dwthandler.h"
#include "util/uintarithsmallmod.h"
#include "util/uintcore.h"
#include "cuComplex.h"
#include <cmath>
#include <complex>
#include <limits>
#include <type_traits>
#include <vector>
#ifdef SIGMA_USE_MSGSL
#include "gsl/span"
#endif

namespace sigma
{
    template <
        typename T_out, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T_out>, double>::value ||
                            std::is_same<std::remove_cv_t<T_out>, std::complex<double>>::value>>
    SIGMA_NODISCARD inline T_out from_complex(std::complex<double> in);

    template <>
    SIGMA_NODISCARD inline double from_complex(std::complex<double> in)
    {
        return in.real();
    }

    template <>
    SIGMA_NODISCARD inline std::complex<double> from_complex(std::complex<double> in)
    {
        return in;
    }

    namespace util
    {
        template <>
        class Arithmetic<std::complex<double>, std::complex<double>, double>
        {
        public:
            Arithmetic()
            {}

            inline std::complex<double> add(const std::complex<double> &a, const std::complex<double> &b) const
            {
                return a + b;
            }

            inline std::complex<double> sub(const std::complex<double> &a, const std::complex<double> &b) const
            {
                return a - b;
            }

            inline std::complex<double> mul_root(const std::complex<double> &a, const std::complex<double> &r) const
            {
                return a * r;
            }

            inline std::complex<double> mul_scalar(const std::complex<double> &a, const double &s) const
            {
                return a * s;
            }

            inline std::complex<double> mul_root_scalar(const std::complex<double> &r, const double &s) const
            {
                return r * s;
            }

            inline std::complex<double> guard(const std::complex<double> &a) const
            {
                return a;
            }
        };
    } // namespace util

    /**
    Provides functionality for encoding vectors of complex or real numbers into
    plaintext polynomials to be encrypted and computed on using the CKKS scheme.
    If the polynomial modulus degree is N, then CKKSEncoder converts vectors of
    N/2 complex numbers into plaintext elements. Homomorphic operations performed
    on such encrypted vectors are applied coefficient (slot-)wise, enabling
    powerful SIMD functionality for computations that are vectorizable. This
    functionality is often called "batching" in the homomorphic encryption
    literature.

    @par Mathematical Background
    Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of
    two, the CKKSEncoder implements an approximation of the canonical embedding
    of the ring of integers Z[X]/(X^N+1) into C^(N/2), where C denotes the complex
    numbers. The Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2)
    whose action on the primitive roots of unity modulo coeff_modulus is easy to
    describe. Since the batching slots correspond 1-to-1 to the primitive roots
    of unity, applying Galois automorphisms on the plaintext acts by permuting
    the slots. By applying generators of the two cyclic subgroups of the Galois
    group, we can effectively enable cyclic rotations and complex conjugations
    of the encrypted complex vectors.
    */
    class CKKSEncoder
    {
        using ComplexArith = util::Arithmetic<std::complex<double>, std::complex<double>, double>;// complex<double>a(1.1,16),b(1,2),c(3,4) double为实部和虚部的类型
        using FFTHandler = util::DWTHandler<std::complex<double>, std::complex<double>, double>;

    public:
        /**
        Creates a CKKSEncoder instance initialized with the specified SIGMAContext.

        @param[in] context The SIGMAContext
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if scheme is not scheme_type::CKKS
        */
        CKKSEncoder(const SIGMAContext &context);

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] parms_id parms_id determining the encryption parameters to
        be used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void encode(
            const std::vector<T> &values, parms_id_type parms_id, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode_internal(values.data(), values.size(), parms_id, scale, destination, std::move(pool));
        }

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        The encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from the
        memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void encode(
            const std::vector<T> &values, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode(values, context_.first_parms_id(), scale, destination, std::move(pool));
        }

        inline void encode_float(
                const float *values, size_t values_size, double scale, Plaintext &destination, cudaStream_t *stream = nullptr) {
            encode_internal(values, values_size, context_.first_parms_id(), scale, destination, stream);
        }
#ifdef SIGMA_USE_MSGSL
        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.
        提供将复数或实数的矢量编码为的功能
        使用CKKS方案来加密和计算明文多项式。
        如果多项式模次为N，则CKKSEncoder转换的矢量为
        N/2个复数转换成明文元素。执行的同态运算
        在这样的加密矢量上按系数（时隙）应用，使
        强大的SIMD功能，用于可向量化的计算。这
        在同态加密中，函数通常被称为“批处理”

        @tparam T Array value type (double or std::complex<double>)
        @param[in] values The array of double-precision floating-point numbers
        (of type T) to encode
        @param[in] parms_id parms_id determining the encryption parameters to
        be used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void encode(
            gsl::span<const T> values, parms_id_type parms_id, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode_internal(
                values.data(), static_cast<std::size_t>(values.size()), parms_id, scale, destination, std::move(pool));
        }

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        The encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from the
        memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Array value type (double or std::complex<double>)
        @param[in] values The array of double-precision floating-point numbers
        (of type T) to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void encode(
            gsl::span<const T> values, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode(values, context_.first_parms_id(), scale, destination, std::move(pool));
        }
#endif
        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. Dynamic
        memory allocations in the process are allocated from the memory pool
        pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            double value, parms_id_type parms_id, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode_internal(value, parms_id, scale, destination, std::move(pool));
        }

        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. The
        encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            double value, double scale, Plaintext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode(value, context_.first_parms_id(), scale, destination, std::move(pool));
        }

        inline void cu_encode(double value, double scale, Plaintext &destination,
                              MemoryPoolHandle pool = MemoryManager::GetPool()) const {
            cu_encode_internal(value, context_.first_parms_id(), scale, destination, std::move(pool));
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            std::complex<double> value, parms_id_type parms_id, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode_internal(value, parms_id, scale, destination, std::move(pool));
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. The encryption parameters used are the
        top level parameters for the given context. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the
        given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(
            std::complex<double> value, double scale, Plaintext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encode(value, context_.first_parms_id(), scale, destination, std::move(pool));
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots.
        @param[in] value The integer number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        */
        inline void encode(std::int64_t value, parms_id_type parms_id, Plaintext &destination) const
        {
            encode_internal(value, parms_id, destination);
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots. The encryption
        parameters used are the top level parameters for the given context.

        @param[in] value The integer number to encode
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        */
        inline void encode(std::int64_t value, Plaintext &destination) const
        {
            encode(value, context_.first_parms_id(), destination);
        }

        /**
        Decodes a plaintext polynomial into double-precision floating-point
        real or complex numbers. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] plain The plaintext to decode
        @param[out] destination The vector to be overwritten with the values in
        the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not in NTT form or is invalid
        for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void decode(
            const Plaintext &plain, std::vector<T> &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            destination.resize(slots_);
            decode_internal(plain, destination.data(), std::move(pool));
        }
#ifdef SIGMA_USE_MSGSL
        /**
        Decodes a plaintext polynomial into double-precision floating-point
        real or complex numbers. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Array value type (double or std::complex<double>)
        @param[in] plain The plaintext to decode
        @param[out] destination The array to be overwritten with the values in
        the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not in NTT form or is invalid
        for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        inline void decode(
            const Plaintext &plain, gsl::span<T> destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            if (destination.size() != slots_)
            {
                throw std::invalid_argument("destination has invalid size");
            }
            decode_internal(plain, destination.data(), std::move(pool));
        }
#endif
        /**
        Returns the number of complex numbers encoded.
        */
        SIGMA_NODISCARD inline std::size_t slot_count() const noexcept
        {
            return slots_;
        }

        void encode_internal(
                const std::complex<double> *values, size_t values_size, parms_id_type parms_id, double scale, Plaintext &destination,
                MemoryPoolHandle pool) const;

    private:

        void encode_internal(
                const float *values, size_t values_size, parms_id_type parms_id, double scale, Plaintext &destination,
                cudaStream_t *stream);

        template <
            typename T, typename = std::enable_if_t<
                            std::is_same<std::remove_cv_t<T>, double>::value ||
                            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
        void decode_internal(const Plaintext &plain, T *destination, MemoryPoolHandle pool) const
        {
            // Verify parameters.
            if (!is_valid_for(plain, context_))
            {
                throw std::invalid_argument("plain is not valid for encryption parameters");
            }
            if (!plain.is_ntt_form())
            {
                throw std::invalid_argument("plain is not in NTT form");
            }
            if (!destination)
            {
                throw std::invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw std::invalid_argument("pool is uninitialized");
            }

            auto &context_data = *context_.get_context_data(plain.parms_id());
            auto &parms = context_data.parms();
            std::size_t coeff_modulus_size = parms.coeff_modulus().size();
            std::size_t coeff_count = parms.poly_modulus_degree();
            std::size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);

            auto ntt_tables = context_data.small_ntt_tables();

            // Check that scale is positive and not too large
            if (plain.scale() <= 0 ||
                (static_cast<int>(log2(plain.scale())) >= context_data.total_coeff_modulus_bit_count()))
            {
                throw std::invalid_argument("scale out of bounds");
            }

            auto decryption_modulus = context_data.total_coeff_modulus();
            auto upper_half_threshold = context_data.upper_half_threshold();
            int logn = util::get_power_of_two(coeff_count);

            // Quick sanity check
            if ((logn < 0) || (coeff_count < SIGMA_POLY_MOD_DEGREE_MIN) || (coeff_count > SIGMA_POLY_MOD_DEGREE_MAX))
            {
                throw std::logic_error("invalid parameters");
            }

            double inv_scale = double(1.0) / plain.scale();

            // Create mutable copy of input
            auto plain_copy(util::allocate_uint(rns_poly_uint64_count, pool));
            util::set_uint(plain.data(), rns_poly_uint64_count, plain_copy.get());

            // Transform each polynomial from NTT domain
            for (std::size_t i = 0; i < coeff_modulus_size; i++)
            {
                util::inverse_ntt_negacyclic_harvey(plain_copy.get() + (i * coeff_count), ntt_tables[i]);
            }

            // CRT-compose the polynomial
            context_data.rns_tool()->base_q()->compose_array(plain_copy.get(), coeff_count, pool);

            // Create floating-point representations of the multi-precision integer coefficients
            double two_pow_64 = std::pow(2.0, 64);
            auto res(util::allocate<std::complex<double>>(coeff_count, pool));
            for (std::size_t i = 0; i < coeff_count; i++)
            {
                res[i] = 0.0;
                if (util::is_greater_than_or_equal_uint(
                        plain_copy.get() + (i * coeff_modulus_size), upper_half_threshold, coeff_modulus_size))
                {
                    double scaled_two_pow_64 = inv_scale;
                    for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
                    {
                        if (plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j])
                        {
                            auto diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                            res[i] += diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                        }
                        else
                        {
                            auto diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                            res[i] -= diff ? static_cast<double>(diff) * scaled_two_pow_64 : 0.0;
                        }
                    }
                }
                else
                {
                    double scaled_two_pow_64 = inv_scale;
                    for (std::size_t j = 0; j < coeff_modulus_size; j++, scaled_two_pow_64 *= two_pow_64)
                    {
                        auto curr_coeff = plain_copy[i * coeff_modulus_size + j];
                        res[i] += curr_coeff ? static_cast<double>(curr_coeff) * scaled_two_pow_64 : 0.0;
                    }
                }

                // Scaling instead incorporated above; this can help in cases
                // where otherwise pow(two_pow_64, j) would overflow due to very
                // large coeff_modulus_size and very large scale
                // res[i] = res_accum * inv_scale;
            }

            fft_handler_.transform_to_rev(res.get(), logn, root_powers_.get());

            for (std::size_t i = 0; i < slots_; i++)
            {
                // TODO: adapt with cuda @wangshuchao
                destination[i] = from_complex<T>(res[static_cast<std::size_t>(host_matrix_reps_index_map_.get()[i])]);
            }
        }

        void encode_internal(
            double value, parms_id_type parms_id, double scale, Plaintext &destination, MemoryPoolHandle pool) const;

        inline void encode_internal(
            std::complex<double> value, parms_id_type parms_id, double scale, Plaintext &destination,
            MemoryPoolHandle pool) const
        {
            auto input = util::allocate<std::complex<double>>(slots_, pool_, value);
            encode_internal(input.get(), slots_, parms_id, scale, destination, std::move(pool));
        }

        void encode_internal(std::int64_t value, parms_id_type parms_id, Plaintext &destination) const;

        void cu_encode_internal(double value, parms_id_type parms_id, double scale, Plaintext &destination, MemoryPoolHandle pool) const;

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        SIGMAContext context_;

        std::size_t slots_;

        std::shared_ptr<util::ComplexRoots> complex_roots_;

        // Holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
        util::Pointer<std::complex<double>> root_powers_;

        // Holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
        util::DeviceArray<cuDoubleComplex> inv_root_powers_;

        util::DeviceArray<std::size_t> matrix_reps_index_map_;
        util::HostArray<std::size_t> host_matrix_reps_index_map_;

//        util::DeviceArray<float> temp_values_;
//        util::DeviceArray<cuDoubleComplex> temp_com_values_;

        ComplexArith complex_arith_;

        FFTHandler fft_handler_;
    };
} // namespace sigma
