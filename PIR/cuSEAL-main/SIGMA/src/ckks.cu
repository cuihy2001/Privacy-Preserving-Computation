// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "ckks.cuh"
#include "kernelutils.cuh"
#include "cuComplex.h"
#include <random>
#include <stdexcept>
#include <cfloat>
#include <thrust/fill.h>
#include <thrust/execution_policy.h>

using namespace std;
using namespace sigma::util;

namespace sigma {
    CKKSEncoder::CKKSEncoder(const SIGMAContext &context) : context_(context) {
        // Verify parameters
        if (!context_.parameters_set()) {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        auto &context_data = *context_.first_context_data();
        if (context_data.parms().scheme() != scheme_type::ckks) {
            throw invalid_argument("unsupported scheme");
        }

        size_t coeff_count = context_data.parms().poly_modulus_degree();
        slots_ = coeff_count >> 1;
        int logn = get_power_of_two(coeff_count);

        host_matrix_reps_index_map_ = HostArray<size_t>(coeff_count);

        // Copy from the matrix to the value vectors
        uint64_t gen = 3;
        uint64_t pos = 1;
        uint64_t m = static_cast<uint64_t>(coeff_count) << 1;
        for (size_t i = 0; i < slots_; i++) {
            // Position in normal bit order
            uint64_t index1 = (pos - 1) >> 1;
            uint64_t index2 = (m - pos - 1) >> 1;

            // Set the bit-reversed locations
            host_matrix_reps_index_map_[i] = safe_cast<size_t>(reverse_bits(index1, logn));
            host_matrix_reps_index_map_[slots_ | i] = safe_cast<size_t>(reverse_bits(index2, logn));

            // Next primitive root
            pos *= gen;
            pos &= (m - 1);
        }

        matrix_reps_index_map_ = host_matrix_reps_index_map_;

        // We need 1~(n-1)-th powers of the primitive 2n-th root, m = 2n
        root_powers_ = allocate<complex<double>>(coeff_count, pool_);
        auto host_inv_root_power = HostArray<cuDoubleComplex>(coeff_count);
        // Powers of the primitive 2n-th root have 4-fold symmetry
        if (m >= 8) {
            complex_roots_ = make_shared<util::ComplexRoots>(util::ComplexRoots(static_cast<size_t>(m), pool_));
            for (size_t i = 1; i < coeff_count; i++) {
                root_powers_[i] = complex_roots_->get_root(reverse_bits(i, logn));
                auto com = complex_roots_->get_root(reverse_bits(i - 1, logn) + 1);
                host_inv_root_power[i] = make_cuDoubleComplex(com.real(), -com.imag());
            }
        } else if (m == 4) {
            root_powers_[1] = {0, 1};
            host_inv_root_power[1] = {0, -1};
        }
        inv_root_powers_ = host_inv_root_power;

        complex_arith_ = ComplexArith();
        fft_handler_ = FFTHandler(complex_arith_);
    }

    __global__ void g_set_conj_values_double(
            const float *values,
            size_t values_size,
            size_t slots,
            cuDoubleComplex *conj_values,
            const uint64_t *matrix_reps_index_map
    ) {
        size_t tid = blockDim.x * blockIdx.x + threadIdx.x;
        auto value = tid >= values_size ? 0 : values[tid];
        conj_values[matrix_reps_index_map[tid]] = {value, 0};
        conj_values[matrix_reps_index_map[tid + slots]] = {value, -0};
    }

    __global__ void g_coeff_modulus_reduce_64(
            cuDoubleComplex *conj_values,
            size_t n,
            size_t coeff_modulus_size,
            const Modulus *coeff_modulus,
            uint64_t *destination
    ) {
        size_t tid = blockDim.x * blockIdx.x + threadIdx.x;
        if (tid >= (n)) {
            return;
        }
        double coeff_d = round(conj_values[tid].x);
        bool is_negative = coeff_d < 0;
        auto coeff_u = static_cast<uint64_t>(abs(coeff_d));
        for (int i = 0; i < coeff_modulus_size; ++i) {
            if (is_negative) {
                destination[tid + i * n] = kernel_util::d_negate_uint_mod(
                        kernel_util::d_barrett_reduce_64(coeff_u, coeff_modulus[i]), coeff_modulus[i]
                );
            } else {
                destination[tid + i * n] = kernel_util::d_barrett_reduce_64(coeff_u, coeff_modulus[i]);
            }
        }
    }

    __global__ void g_fft_transfer_from_rev_layered(
            size_t layer,
            cuDoubleComplex *operand,
            size_t poly_modulus_degree_power,
            const cuDoubleComplex *roots
    ) {
        size_t global_tid = blockDim.x * blockIdx.x + threadIdx.x;
        size_t m = 1 << (poly_modulus_degree_power - 1 - layer);
        size_t gap = 1 << layer;
        size_t rid = (1 << poly_modulus_degree_power) - (m << 1) + 1 + (global_tid >> layer);
        size_t coeff_index = ((global_tid >> layer) << (layer + 1)) + (global_tid & (gap - 1));

        cuDoubleComplex &x = operand[coeff_index];
        cuDoubleComplex &y = operand[coeff_index + gap];

        double ur = x.x, ui = x.y, vr = y.x, vi = y.y;
        double rr = roots[rid].x, ri = roots[rid].y;

        // x = u + v
        x.x = ur + vr;
        x.y = ui + vi;

        // y = (u-v) * r
        ur -= vr;
        ui -= vi; // u <- u - v
        y.x = ur * rr - ui * ri;
        y.y = ur * ri + ui * rr;
    }

    __global__ void g_multiply_scalar(
            cuDoubleComplex *operand,
            double scalar
    ) {
        size_t global_tid = blockDim.x * blockIdx.x + threadIdx.x;
        operand[global_tid].x *= scalar;
        operand[global_tid].y *= scalar;
    }

    void k_fft_transfer_from_rev(
            cuDoubleComplex *operand,
            size_t poly_modulus_degree_power,
            const cuDoubleComplex *roots,
            double fix = 1
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        std::size_t m = n >> 1;
        std::size_t layer = 0;
        auto size = n >> 1;
        for (; m >= 1; m >>= 1) {
            g_fft_transfer_from_rev_layered<<<size / 128, 128>>>(layer, operand, poly_modulus_degree_power, roots);
            layer++;
        }
        if (fix != 1) {
            g_multiply_scalar<<<n / 128, 128>>>(operand, fix);
        }
    }

    void k_fft_transfer_from_rev(
            cuDoubleComplex *operand,
            size_t poly_modulus_degree_power,
            const cuDoubleComplex *roots,
            double fix,
            cudaStream_t &stream
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        std::size_t m = n >> 1;
        std::size_t layer = 0;
        auto size = n >> 1;
        for (; m >= 1; m >>= 1) {
            g_fft_transfer_from_rev_layered<<<size / 128, 128, 0, stream>>>(layer, operand, poly_modulus_degree_power,
                                                                            roots);
            layer++;
        }
        if (fix != 1) {
            g_multiply_scalar<<<n / 128, 128, 0, stream>>>(operand, fix);
        }
    }

    void CKKSEncoder::encode_internal(
            const float *values, size_t values_size, parms_id_type parms_id, double scale, Plaintext &destination,
            cudaStream_t *stream) {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr) {
            throw std::invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!values && values_size > 0) {
            throw std::invalid_argument("values cannot be null");
        }
        if (values_size > slots_) {
            throw std::invalid_argument("values_size is too large");
        }

        auto &context_data = *context_data_ptr;
        auto &params = context_data.parms();
        auto &coeff_modulus = params.device_coeff_modulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = params.poly_modulus_degree();

        // Quick sanity check
        if (!util::product_fits_in(coeff_modulus_size, coeff_count)) {
            throw std::logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) + 1 >= context_data.total_coeff_modulus_bit_count())) {
            throw std::invalid_argument("scale out of bounds");
        }

        auto ntt_tables = context_data.device_small_ntt_tables();

        // values_size is guaranteed to be no bigger than slots_
        std::size_t n = util::mul_safe(slots_, std::size_t(2));

        destination.temp_values_.resize(slots_);
        destination.temp_com_values_.resize(coeff_count);

        if (stream == nullptr) {
            KernelProvider::copy(destination.temp_values_.get(), values, values_size);
            g_set_conj_values_double<<<slots_ / 128, 128>>>(
                    destination.temp_values_.get(),
                    values_size,
                    slots_,
                    destination.temp_com_values_.get(),
                    matrix_reps_index_map_.get()
            );

            double fix = scale / static_cast<double>(n);
            k_fft_transfer_from_rev(destination.temp_com_values_.get(), util::get_power_of_two(n),
                                    inv_root_powers_.get(), fix);
        } else {
            KernelProvider::copyAsync(destination.temp_values_.get(), values, values_size, *stream);
            g_set_conj_values_double<<<slots_ / 128, 128, 0, *stream>>>(
                    destination.temp_values_.get(),
                    values_size,
                    slots_,
                    destination.temp_com_values_.get(),
                    matrix_reps_index_map_.get()
            );

            double fix = scale / static_cast<double>(n);
            k_fft_transfer_from_rev(destination.temp_com_values_.get(), util::get_power_of_two(n),
                                    inv_root_powers_.get(), fix, *stream);
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;

        auto dest_size = util::mul_safe(coeff_count, coeff_modulus_size);

        destination.device_resize(dest_size);

        if (stream == nullptr) {
            g_coeff_modulus_reduce_64<<<n / 128, 128>>>(
                    destination.temp_com_values_.get(),
                    n,
                    coeff_modulus_size,
                    coeff_modulus.get(),
                    destination.device_data()
            );

            // Transform to NTT domain
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                kernel_util::g_ntt_negacyclic_harvey(destination.device_data() + i * coeff_count, coeff_count,
                                                     ntt_tables[i]);
            }
        } else {
            g_coeff_modulus_reduce_64<<<n / 128, 128, 0, *stream>>>(
                    destination.temp_com_values_.get(),
                    n,
                    coeff_modulus_size,
                    coeff_modulus.get(),
                    destination.device_data()
            );

            // Transform to NTT domain
            for (std::size_t i = 0; i < coeff_modulus_size; i++) {
                kernel_util::g_ntt_negacyclic_harvey(destination.device_data() + i * coeff_count, coeff_count,
                                                     ntt_tables[i], *stream);
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoder::encode_internal(
            double value, parms_id_type parms_id, double scale, Plaintext &destination, MemoryPoolHandle pool) const {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr) {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!pool) {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.poly_modulus_degree();

        // Quick sanity check
        if (!product_fits_in(coeff_modulus_size, coeff_count)) {
            throw logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) >= context_data.total_coeff_modulus_bit_count())) {
            throw invalid_argument("scale out of bounds");
        }

        // Compute the scaled value
        value *= scale;

        int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
        if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count()) {
            throw invalid_argument("encoded value is too large");
        }

        double two_pow_64 = pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;
        destination.resize(coeff_count * coeff_modulus_size);

        double coeffd = round(value);
        bool is_negative = signbit(coeffd);
        coeffd = fabs(coeffd);

        // Use faster decomposition methods when possible
        if (coeff_bit_count <= 64) {
            uint64_t coeffu = static_cast<uint64_t>(fabs(coeffd));

            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(
                            destination.data() + (j * coeff_count), coeff_count,
                            negate_uint_mod(barrett_reduce_64(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(
                            destination.data() + (j * coeff_count), coeff_count,
                            barrett_reduce_64(coeffu, coeff_modulus[j]));
                }
            }
        } else if (coeff_bit_count <= 128) {
            uint64_t coeffu[2]{static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                               static_cast<uint64_t>(coeffd / two_pow_64)};

            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(
                            destination.data() + (j * coeff_count), coeff_count,
                            negate_uint_mod(barrett_reduce_128(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(
                            destination.data() + (j * coeff_count), coeff_count,
                            barrett_reduce_128(coeffu, coeff_modulus[j]));
                }
            }
        } else {
            // Slow case
            auto coeffu(allocate_uint(coeff_modulus_size, pool));

            // We are at this point guaranteed to fit in the allocated space
            set_zero_uint(coeff_modulus_size, coeffu.get());
            auto coeffu_ptr = coeffu.get();
            while (coeffd >= 1) {
                *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                coeffd /= two_pow_64;
            }

            // Next decompose this coefficient
            context_data.rns_tool()->base_q()->decompose(coeffu.get(), pool);

            // Finally replace the sign if necessary
            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(
                            destination.data() + (j * coeff_count), coeff_count,
                            negate_uint_mod(coeffu[j], coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    fill_n(destination.data() + (j * coeff_count), coeff_count, coeffu[j]);
                }
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoder::cu_encode_internal(
            double value, parms_id_type parms_id, double scale, Plaintext &destination, MemoryPoolHandle pool) const {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr) {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!pool) {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.poly_modulus_degree();

        // Quick sanity check
        if (!product_fits_in(coeff_modulus_size, coeff_count)) {
            throw logic_error("invalid parameters");
        }

        // Check that scale is positive and not too large
        if (scale <= 0 || (static_cast<int>(log2(scale)) >= context_data.total_coeff_modulus_bit_count())) {
            throw invalid_argument("scale out of bounds");
        }

        // Compute the scaled value
        value *= scale;

        int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
        if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count()) {
            throw invalid_argument("encoded value is too large");
        }

        double two_pow_64 = pow(2.0, 64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;
        destination.device_resize(coeff_count * coeff_modulus_size);

        double coeffd = round(value);
        bool is_negative = signbit(coeffd);
        coeffd = fabs(coeffd);

        // Use faster decomposition methods when possible
        if (coeff_bit_count <= 64) {
            uint64_t coeffu = static_cast<uint64_t>(fabs(coeffd));

            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   negate_uint_mod(barrett_reduce_64(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   barrett_reduce_64(coeffu, coeff_modulus[j]));
                }
            }
        } else if (coeff_bit_count <= 128) {
            uint64_t coeffu[2]{static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                               static_cast<uint64_t>(coeffd / two_pow_64)};

            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   negate_uint_mod(barrett_reduce_128(coeffu, coeff_modulus[j]), coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   barrett_reduce_128(coeffu, coeff_modulus[j]));
                }
            }
        } else {
            // Slow case
            auto coeffu(allocate_uint(coeff_modulus_size, pool));

            // We are at this point guaranteed to fit in the allocated space
            set_zero_uint(coeff_modulus_size, coeffu.get());
            auto coeffu_ptr = coeffu.get();
            while (coeffd >= 1) {
                *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                coeffd /= two_pow_64;
            }

            // Next decompose this coefficient
            context_data.rns_tool()->base_q()->decompose(coeffu.get(), pool);

            // Finally replace the sign if necessary
            if (is_negative) {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   negate_uint_mod(coeffu[j], coeff_modulus[j]));
                }
            } else {
                for (size_t j = 0; j < coeff_modulus_size; j++) {
                    thrust::fill_n(thrust::device, destination.device_data() + (j * coeff_count), coeff_count,
                                   coeffu[j]);
                }
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = scale;
    }

    void CKKSEncoder::encode_internal(int64_t value, parms_id_type parms_id, Plaintext &destination) const {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr) {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t coeff_count = parms.poly_modulus_degree();

        // Quick sanity check
        if (!product_fits_in(coeff_modulus_size, coeff_count)) {
            throw logic_error("invalid parameters");
        }

        int coeff_bit_count = get_significant_bit_count(static_cast<uint64_t>(llabs(value))) + 2;
        if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count()) {
            throw invalid_argument("encoded value is too large");
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.parms_id() = parms_id_zero;
        destination.resize(coeff_count * coeff_modulus_size);

        if (value < 0) {
            for (size_t j = 0; j < coeff_modulus_size; j++) {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp += coeff_modulus[j].value();
                tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        } else {
            for (size_t j = 0; j < coeff_modulus_size; j++) {
                uint64_t tmp = static_cast<uint64_t>(value);
                tmp = barrett_reduce_64(tmp, coeff_modulus[j]);
                fill_n(destination.data() + (j * coeff_count), coeff_count, tmp);
            }
        }

        destination.parms_id() = parms_id;
        destination.scale() = 1.0;
    }

    void CKKSEncoder::encode_internal(const std::complex<double> *values, size_t values_size, parms_id_type parms_id,
                                      double scale, Plaintext &destination, MemoryPoolHandle pool) const {
//        encode_internal_cu(values, values_size, parms_id, scale, destination, pool);
    }
} // namespace sigma
