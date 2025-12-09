
#pragma once

#include "kernelprovider.cuh"
#include "kernelutils.cuh"
#include "util/devicearray.cuh"
#include "util/hostarray.h"
#include "util/uintarithsmallmod.h"
#include "util/ntt.h"
#include "modulus.h"
#include "util/uint128_ntt.h"

namespace sigma {

    namespace util {
        class RandomGenerator;
    }

    namespace kernel_util {

        using sigma::util::MultiplyUIntModOperand;

        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s) {
            return util::DeviceArray<uint64_t>(s);
        }

        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t) {
            return util::DeviceArray<uint64_t>(s * t);
        }

        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t, uint64_t u) {
            return util::DeviceArray<uint64_t>(s * t * u);
        }

        template <typename T>
        inline util::DeviceArray<T> kAllocateZero(size_t size) {
            auto ret = util::DeviceArray<T>(size);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }

        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t) {
            auto ret = util::DeviceArray<uint64_t>(s * t);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }

        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t, uint64_t u) {
            auto ret = util::DeviceArray<uint64_t>(s * t * u);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }


        inline size_t ceilDiv_(size_t a, size_t b) {
            return (a % b) ? (a / b + 1) : (a / b);
        }

        __device__ inline void d_multiply_uint64_hw64(uint64_t operand1, uint64_t operand2, uint64_t *hw64) {
            *hw64 = static_cast<uint64_t>(
                    ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64));
        }//截断取前六十四位

        __device__ inline void d_multiply_uint64(uint64_t operand1, uint64_t operand2, uint64_t *result128) {
            uint128_t product = static_cast<uint128_t>(operand1) * operand2;
            result128[0] = static_cast<uint64_t>(product);
            result128[1] = static_cast<uint64_t>(product >> 64);//64乘法，结果存为两个64
        }

        __device__ inline unsigned char d_add_uint64(uint64_t operand1, uint64_t operand2, unsigned char carry, uint64_t *result) {
            operand1 += operand2;
            *result = operand1 + carry;
            return (operand1 < operand2) || (~operand1 < carry);
        }

        __device__ inline unsigned char d_add_uint64(uint64_t operand1, uint64_t operand2, uint64_t *result) {
            *result = operand1 + operand2;
            return static_cast<unsigned char>(*result < operand1);//比较大小返回0/1
        }

        __device__ inline unsigned char d_add_uint128(uint64_t* operand1, uint64_t* operand2, uint64_t* result) {
            unsigned char carry = d_add_uint64(operand1[0], operand2[0], result);
            return d_add_uint64(operand1[1], operand2[1], carry, result + 1);
        }

        __device__ inline uint64_t d_barrett_reduce_64(uint64_t input, const Modulus &modulus) {
            uint64_t tmp[2];
            const std::uint64_t *const_ratio = modulus.const_ratio();
            d_multiply_uint64_hw64(input, const_ratio[1], tmp + 1);
            uint64_t modulusValue = modulus.value();
            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulusValue;

            // One more subtraction is enough
            return (tmp[0] >= modulusValue) ? (tmp[0] - modulusValue) : (tmp[0]);
        }

        __device__ inline uint64_t d_barrett_reduce_128(const uint64_t *input, const Modulus &modulus)
        {
            // Reduces input using base 2^64 Barrett reduction
            // input allocation size must be 128 bits

            uint64_t tmp1, tmp2[2], tmp3, carry;
            const std::uint64_t *const_ratio = modulus.const_ratio();;

            // Multiply input and const_ratio
            // Round 1
            d_multiply_uint64_hw64(input[0], const_ratio[0], &carry);

            d_multiply_uint64(input[0], const_ratio[1], tmp2);
            tmp3 = tmp2[1] + d_add_uint64(tmp2[0], carry, &tmp1);

            // Round 2
            d_multiply_uint64(input[1], const_ratio[0], tmp2);
            carry = tmp2[1] + d_add_uint64(tmp1, tmp2[0], &tmp1);

            // This is all we care about
            tmp1 = input[1] * const_ratio[1] + tmp3 + carry;

            // Barrett subtraction
            uint64_t modulus_value = modulus.value();
            tmp3 = input[0] - tmp1 * modulus_value;

            // One more subtraction is enough
            return (tmp3 >= modulus_value) ? (tmp3 - modulus_value): (tmp3);
        }

        __device__ inline uint64_t d_add_uint_mod(
                std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            // Sum of operands modulo Modulus can never wrap around 2^64
            operand1 += operand2;
            uint64_t modulus_value = modulus.value();
            return (operand1 >= modulus_value) ? (operand1 - modulus_value) : (operand1);
        }

        __device__ inline unsigned char d_sub_uint_64(
                std::uint64_t operand1, std::uint64_t operand2, unsigned char borrow, unsigned long long *result)
        {
            auto diff = operand1 - operand2;
            *result = diff - (borrow != 0);
            return (diff > operand1) || (diff < borrow);
        }

        __device__ inline unsigned char d_sub_uint_64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
            *result = operand1 - operand2;
            return static_cast<unsigned char>(operand2 > operand1);
        }

        __device__ inline uint64_t d_sub_uint_mod(
                std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
            unsigned long long temp;
            int64_t borrow = static_cast<std::int64_t>(d_sub_uint_64(operand1, operand2, 0, &temp));
            return static_cast<std::uint64_t>(temp) + (modulus.value() & static_cast<std::uint64_t>(-borrow));
        }

        __device__
        inline uint64_t d_multiply_uint_mod(std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus)
        {

            uint64_t tmp1, tmp2;
            const std::uint64_t p = modulus.value();
            d_multiply_uint64_hw64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return SIGMA_COND_SELECT(tmp2 >= p, tmp2 - p, tmp2);
        }
        __device__
        inline uint64_t d_multiply_uint_mod_lazy(std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus) {
            uint64_t tmp1;
            const uint64_t p = modulus.value();
            d_multiply_uint64_hw64(x, y.quotient, &tmp1);
            return y.operand * x - tmp1 * p;
        }

        __device__ inline std::uint64_t d_negate_uint_mod(std::uint64_t operand, const Modulus &modulus) {
            auto non_zero = static_cast<std::int64_t>(operand != 0);
            return (modulus.value() - operand) & static_cast<std::uint64_t>(-non_zero);
        }

        __device__ inline void dDivideUint128Inplace(std::uint64_t *numerator, std::uint64_t denominator, std::uint64_t *quotient)
        {
            uint128_t n, q;
            n = (static_cast<uint128_t>(numerator[1]) << 64) | (static_cast<uint128_t>(numerator[0]));
            q = n / denominator;
            n -= q * denominator;
            numerator[0] = static_cast<std::uint64_t>(n);
            numerator[1] = 0;
            quotient[0] = static_cast<std::uint64_t>(q);
            quotient[1] = static_cast<std::uint64_t>(q >> 64);
        }

        void g_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables);

        void g_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables, cudaStream_t &cudaStream);

        void g_inv_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables);

        void g_inv_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables, cudaStream_t &stream);

        void dyadic_product_coeffmod(
                const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count, size_t ntt_size,
                size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result);

        void dyadic_product_coeffmod(
                const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count,size_t ntt_size,
                size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result, cudaStream_t &stream);

        void dyadic_product_coeffmod_optimize(
                const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count, size_t encrypted_size,
                size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result);

        void sample_poly_cbd(
                util::RandomGenerator *random_generator, const Modulus *coeff_modulus, size_t coeff_modulus_size,
                size_t coeff_count, uint64_t *destination);

        void sample_poly_cbd(
                util::RandomGenerator *random_generator, const Modulus *coeff_modulus, size_t coeff_modulus_size,
                size_t coeff_count, uint64_t *destination, cudaStream_t &stream);

        void add_negate_add_poly_coeffmod(
                const uint64_t *operand1, const uint64_t *operand2, const uint64_t *operand3, std::size_t coeff_count,
                uint64_t modulus_value, uint64_t *result);

        void add_negate_add_poly_coeffmod(
                const uint64_t *operand1, const uint64_t *operand2, const uint64_t *operand3, std::size_t coeff_count,
                uint64_t modulus_value, uint64_t *result, cudaStream_t &stream);

        void add_poly_coeffmod(
                const uint64_t *operand1, const uint64_t *operand2, size_t size, size_t coeff_modulus_size,
                std::size_t coeff_count, uint64_t modulus_value, uint64_t *result);

        void negacyclic_multiply_poly_mono_coeffmod(
                uint64_t* poly, std::size_t poly_size, std::size_t coeff_count,
                std::uint64_t coeff_modulus_size, std::uint64_t mono_coeff,
                std::size_t mono_exponent, Modulus &modulus, uint64_t* result);

        void d_multiply_poly_scalar_coeffmod(uint64_t* poly_array, size_t poly_size, size_t coeff_modulus_size,
                size_t poly_modulus_degree, uint64_t scalar, Modulus* modulus, uint64_t* result);


        void d_modulo_poly_coeffs(
                uint64_t* operand,
                std::size_t coeff_count,
                const Modulus &modulus,
                uint64_t* result
        );

        void d_negacyclic_shift_poly_coeffmod(
                uint64_t* poly,
                size_t coeff_count,//N
                size_t shift,
                size_t coeff_mod_count,
                const Modulus *modulus,
                uint64_t* result);

        void d_inverse_ntt_negacyclic_harvey_lazy(
                uint64_t* operand,
                size_t poly_size,
                size_t coeff_modulus_size,
                size_t poly_modulus_degree_power,
                const util::NTTTables &ntt_tables);

        void d_inverse_ntt_negacyclic_harvey(
                uint64_t* operand,
                size_t poly_size,
                size_t coeff_modulus_size,
                size_t poly_modulus_degree_power,
                const util::NTTTables &ntt_tables);

        void kDyadicProductCoeffmod(
                uint64_t* operand1,
                uint64_t* operand2,
                size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree,
                const Modulus &moduli,
                uint64_t* output);

    }

}
