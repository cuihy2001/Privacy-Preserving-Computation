
#include "kernelutils.cuh"
#include "util/randomgenerator.cuh"

namespace sigma::kernel_util {

    __global__ void g_dyadic_product_coeffmod(//利用Barrett reduction加速
            const uint64_t *operand1,
            const uint64_t *operand2,
            const uint64_t modulus_value,
            const uint64_t const_ratio_0,//？
            const uint64_t const_ratio_1,
            uint64_t *result) {

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;//线程索引

        // Reduces z using base 2^64 Barrett reduction
        uint64_t z[2], tmp1, tmp2[2], tmp3, carry;
        d_multiply_uint64(*(operand1 + tid), *(operand2 + tid), z);//线程分别相乘存在z

        // Multiply input and const_ratio
        // Round 1
        d_multiply_uint64_hw64(z[0], const_ratio_0, &carry);
        d_multiply_uint64(z[0], const_ratio_1, tmp2);
        tmp3 = tmp2[1] + d_add_uint64(tmp2[0], carry, &tmp1);

        // Round 2
        d_multiply_uint64(z[1], const_ratio_0, tmp2);
        carry = tmp2[1] + d_add_uint64(tmp1, tmp2[0], &tmp1);

        // This is all we care about
        tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

        // Barrett subtraction
        tmp3 = z[0] - tmp1 * modulus_value;

        // Claim: One more subtraction is enough
        *(result + tid) = tmp3 >= modulus_value ? tmp3 - modulus_value : tmp3;

    }

    void dyadic_product_coeffmod(//参数设置
            const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count, size_t ntt_size,
            size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result) {
#ifdef SIGMA_DEBUG
        if (operand1 == nullptr || operand2 == nullptr || result == nullptr) {
            throw std::invalid_argument("nullptr");
        }
#endif
        const uint64_t modulus_value = modulus.value();
        const uint64_t const_ratio_0 = modulus.const_ratio()[0];
        const uint64_t const_ratio_1 = modulus.const_ratio()[1];

        uint blockDim = coeff_count * ntt_size * coeff_modulus_size / 128;

        g_dyadic_product_coeffmod<<<blockDim, 128>>>(
                operand1,
                operand2,
                modulus_value,
                const_ratio_0,
                const_ratio_1,
                result);

    }

    void dyadic_product_coeffmod(//设置数据流，用来实现GPU上的数据流并行
            const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count, size_t ntt_size,
            size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result, cudaStream_t &stream) {

        const uint64_t modulus_value = modulus.value();
        const uint64_t const_ratio_0 = modulus.const_ratio()[0];
        const uint64_t const_ratio_1 = modulus.const_ratio()[1];

        uint threadDim = 128;
        uint blockDim = coeff_count * ntt_size * coeff_modulus_size / threadDim;

        g_dyadic_product_coeffmod<<<blockDim, threadDim, 0, stream>>>(
                operand1,
                operand2,
                modulus_value,
                const_ratio_0,
                const_ratio_1,
                result);

    }

    __global__ void g_dyadic_product_coeffmod_optimize(//利用Barrett reduction加速
            const uint64_t *operand1,
            const uint64_t *operand2,
            const uint64_t modulus_value,
            const uint64_t const_ratio_0,//？
            const uint64_t const_ratio_1,
            uint64_t *result,
            uint64_t poly_number,
            uint64_t poly_size) {

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;//线程索引


        #pragma unroll
        for(int i = 0; i < poly_number; i++) {
            // Reduces z using base 2^64 Barrett reduction
            uint64_t z[2], tmp1, tmp2[2], tmp3, carry;
            d_multiply_uint64(*(operand1 + tid + i * poly_size), *(operand2 + tid), z);//线程分别相乘存在z

            // Multiply input and const_ratio
            // Round 1
            d_multiply_uint64_hw64(z[0], const_ratio_0, &carry);
            d_multiply_uint64(z[0], const_ratio_1, tmp2);
            tmp3 = tmp2[1] + d_add_uint64(tmp2[0], carry, &tmp1);

            // Round 2
            d_multiply_uint64(z[1], const_ratio_0, tmp2);
            carry = tmp2[1] + d_add_uint64(tmp1, tmp2[0], &tmp1);

            // This is all we care about
            tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

            // Barrett subtraction
            tmp3 = z[0] - tmp1 * modulus_value;

            // Claim: One more subtraction is enough
            *(result + tid + i * poly_size) = tmp3 >= modulus_value ? tmp3 - modulus_value : tmp3;
        }

    }

    void dyadic_product_coeffmod_optimize(
            const uint64_t *operand1, const uint64_t *operand2, size_t coeff_count, size_t encrypted_size,
            size_t coeff_modulus_size, const Modulus &modulus, uint64_t *result)
    {
        uint64_t modulus_value[coeff_modulus_size];
        uint64_t const_ratio_0[coeff_modulus_size];
        uint64_t const_ratio_1[coeff_modulus_size];
        for(int i = 0; i < coeff_modulus_size; i++){
            modulus_value[i] = (&modulus + i)->value();
            const_ratio_0[i] = (&modulus + i)->const_ratio()[0];
            const_ratio_1[i] = (&modulus + i)->const_ratio()[1];
        }

        uint64_t poly_size = coeff_count * coeff_modulus_size;
        for(int  i = 0; i < coeff_modulus_size; i++){
            int blockDim = ceil(coeff_count / (1024.0));
            g_dyadic_product_coeffmod_optimize<<<blockDim, 1024>>>(
                    operand1 + i * coeff_count,
                    operand2 + i * coeff_count,
                    modulus_value[i],
                    const_ratio_0[i],
                    const_ratio_1[i],
                    result + i * coeff_count,
                    encrypted_size,
                    poly_size);
        }
    }

    template<unsigned l, unsigned n>
    __global__ void ct_ntt_inner(uint64_t *values, const util::NTTTables &tables) {

        const MultiplyUIntModOperand *roots = tables.get_from_device_root_powers();
        const Modulus &modulus = tables.modulus();

        auto modulus_value = modulus.value();
        auto two_times_modulus = modulus_value << 1;//把模值乘2

        auto global_tid = blockIdx.x * 1024 + threadIdx.x;
        auto step = (n / l) / 2;//步长
        auto psi_step = global_tid / step;
        auto target_index = psi_step * step * 2 + global_tid % step;

        const MultiplyUIntModOperand &r = roots[l + psi_step];

        uint64_t &x = values[target_index];
        uint64_t &y = values[target_index + step];
        uint64_t u = x >= two_times_modulus ? x - two_times_modulus : x;
        uint64_t v = d_multiply_uint_mod_lazy(y, r, modulus);
        x = u + v;
        y = u + two_times_modulus - v;
    }

    template<unsigned l, unsigned n>
    __global__ void
    ct_inv_ntt_inner(uint64_t *values, const util::NTTTables &tables, const MultiplyUIntModOperand *scalar = NULL) {

        const MultiplyUIntModOperand *roots = tables.get_from_device_inv_root_powers();
        const Modulus &modulus = tables.modulus();

        auto modulus_value = modulus.value();
        auto two_times_modulus = modulus_value << 1;//把模值乘2

        auto length = l;

        auto global_tid = blockIdx.x * 1024 + threadIdx.x;
        auto step = (n / length) / 2;//步长 0 1 2 3
        auto psi_step = global_tid / step;//0-37892/2 37892/2-37892 0 1 2 3
        auto target_index = psi_step * step * 2 + global_tid % step;//0 2 4 6 +
        const MultiplyUIntModOperand &r = roots[length + psi_step];
        //if (scalar == NULL) {//
        uint64_t &u = values[target_index];
        uint64_t &v = values[target_index + step];
        uint64_t x = u;
        uint64_t y = v;
        //uint64_t temp1 = x + y;
        //uint64_t temp2 = x + two_times_modulus - y;
        u = x + y >= two_times_modulus ? (x + y - two_times_modulus) : x + y;
        v = d_multiply_uint_mod_lazy(x + two_times_modulus - y, r, modulus);
    }

    template<uint l, uint n>
    //1 4096 block数量 block线程数量 2048 1024 512 256 128 64 32 16
    __global__ void ct_ntt_inner_single(uint64_t *values, const util::NTTTables &tables) {
        auto local_tid = threadIdx.x;

        const MultiplyUIntModOperand *roots = tables.get_from_device_root_powers();
        const Modulus &modulus = tables.modulus();

        extern __shared__ uint64_t shared_array[];

#pragma unroll
        for (uint iteration_num = 0; iteration_num < (n / 1024 / l); iteration_num++) {//1 4096
            auto global_tid = local_tid + iteration_num * 1024;
            shared_array[global_tid] = values[global_tid + blockIdx.x * (n / l)];
        }

        auto modulus_value = modulus.value();
        auto two_times_modulus = modulus_value << 1;

        auto step = n / l;//2048
#pragma unrollx
        for (uint length = l; length < n; length <<= 1) {//1 4096 length root表的位移
            step >>= 1;//1024

#pragma unroll
            for (uint iteration_num = 0; iteration_num < (n / 1024 / l) / 2; iteration_num++) {
                auto global_tid = local_tid + iteration_num * 1024;
                auto psi_step = global_tid / step;
                auto target_index = psi_step * step * 2 + global_tid % step;
                psi_step = (global_tid + blockIdx.x * (n / l / 2)) / step;

                const MultiplyUIntModOperand &r = roots[length + psi_step];

                uint64_t &x = shared_array[target_index];
                uint64_t &y = shared_array[target_index + step];
                uint64_t u = x >= two_times_modulus ? x - two_times_modulus : x;
                uint64_t v = d_multiply_uint_mod_lazy(y, r, modulus);
                x = u + v;
                y = u + two_times_modulus - v;
/*                uint64_t u = x;
                uint64_t v = y;
                x = (u+v)%modulus_value;
                y = (u-r.operand*y)%modulus_value;*/
            }
            __syncthreads();
        }

        uint64_t value;
#pragma unroll
        for (int iteration_num = 0; iteration_num < (n / 1024 / l); iteration_num++) {
            auto global_tid = local_tid + iteration_num * 1024;
            value = shared_array[global_tid];
            if (value >= two_times_modulus) {
                value -= two_times_modulus;
            }
            if (value >= modulus_value) {
                value -= modulus_value;
            }

            values[global_tid + blockIdx.x * (n / l)] = value;
        }
    }

    template<uint l, uint n>//2 4096
    //1 4096 block数量 block线程数量 2048 1024 512 256 128 64 32 16
    __global__ void ct_inv_ntt_inner_single(uint64_t *values, const util::NTTTables &tables) {
        auto local_tid = threadIdx.x;//共2048个 <2,1024>

        const MultiplyUIntModOperand *roots = tables.get_from_device_inv_root_powers();//4096
        const Modulus &modulus = tables.modulus();

        __shared__ uint64_t shared_array[2048];
        //printf("there\n");
#pragma unroll
        for (uint iteration_num = 0; iteration_num < (n / 1024 / l); iteration_num++) {//2
            auto global_tid = local_tid + iteration_num * 1024;//1024个线程迭代四次赋值
            shared_array[global_tid] = values[global_tid + blockIdx.x * (n / l)];//shared_array赋值
            /*printf("%d ",global_tid);*/
        }
        //printf("there");

        auto modulus_value = modulus.value();
        auto two_times_modulus = modulus_value << 1;

        //auto step = l;//1
        __syncthreads();

#pragma unrollx
        for (uint length = (n / 2); length >= 1; length /= 2) {//length:1-2048
            //printf("there");

            auto step = (n / length) / 2;
#pragma unroll
            for (uint iteration_num = 0; iteration_num < (n / 1024 / l) / 2; iteration_num++) {//2
                //printf("%d ",iteration_num);
                auto global_tid = local_tid + iteration_num * 1024;//一共就使用了1024线程，整体平移1024继续迭代
                auto psi_step = global_tid / step;//2048 0
                auto target_index = psi_step * step * 2 + global_tid % step;

                psi_step = (global_tid + blockIdx.x * (n / l / 2)) / step;

                const MultiplyUIntModOperand &r = roots[length + psi_step];

                uint64_t &u = shared_array[target_index];
                uint64_t &v = shared_array[target_index + step];
                uint64_t x = u;
                uint64_t y = v;

                //printf("%d ",temp1);
                u = x + y >= two_times_modulus ? (x + y - two_times_modulus) : x + y;

                v = d_multiply_uint_mod_lazy(x + two_times_modulus - y, r, modulus);
                //printf("%d ",v);

            }
            __syncthreads();
        }
        uint64_t value;
#pragma unroll
        for (int iteration_num = 0; iteration_num < (n / 1024 / l); iteration_num++) {
            auto global_tid = local_tid + iteration_num * 1024;

            value = shared_array[global_tid];

/*
            if (value >= two_times_modulus) {
                value -= two_times_modulus;
            }

            if (value >= modulus_value) {
                value -= modulus_value;
            }
*/
            values[global_tid + blockIdx.x * (n / l)] = value;
        }
    }

    __global__ void g_multiply_inv_degree_ntt_tables(uint64_t* poly_array, const util::NTTTables &tables) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        const Modulus &modulus = tables.modulus();
        uint64_t modulus_value = modulus.value();

        MultiplyUIntModOperand scalar = tables.inv_degree_modulo();
        uint64_t value = poly_array[tid];
        value = d_multiply_uint_mod_lazy(value, scalar, modulus);

        poly_array[tid] = value;
    }

    __global__ void g_mod_using_ntt_tables(
            uint64_t* operand,
            const util::NTTTables &ntt_tables)
    {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        uint64_t modulus_value = ntt_tables.modulus().value();
        uint64_t twice_modulus_value = modulus_value << 1;
        size_t id =  tid;
        if (operand[id] >= twice_modulus_value) operand[id] -= twice_modulus_value;
        if (operand[id] >= modulus_value) operand[id] -= modulus_value;
    }

    void g_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables) {
        switch (coeff_count) {
            case 32768: {
                ct_ntt_inner<1, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);//一半执行就行
                ct_ntt_inner<2, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_ntt_inner<4, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_ntt_inner_single<8, 32768><<<8, 1024, 4096 * sizeof(uint64_t)>>>(operand,
                                                                                    tables);//4096 * sizeof(uint64_t)动态分配的共享内存大小
                break;
            }
            case 16384: {
                ct_ntt_inner<1, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_ntt_inner<2, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_ntt_inner_single<4, 16384><<<4, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 8192: {
                ct_ntt_inner<1, 8192><<<8192 / 1024 / 2, 1024>>>(operand, tables);
                ct_ntt_inner_single<2, 8192><<<2, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 4096: {
                ct_ntt_inner_single<1, 4096> <<<1, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 2048: {
                ct_ntt_inner_single<1, 2048> <<<1, 1024, 2048 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            default:
                throw std::invalid_argument("not support");
        }
        CHECK(cudaGetLastError());
    }

    void g_inv_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables) {
        switch (coeff_count) {
            case 32768: {
                ct_inv_ntt_inner<1, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);//一半执行就行
                ct_inv_ntt_inner<2, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner<4, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<8, 32768><<<8, 1024, 4096 * sizeof(uint64_t)>>>(operand,
                                                                                        tables);//4096 * sizeof(uint64_t)动态分配的共享内存大小
                break;
            }
            case 16384: {
                ct_inv_ntt_inner<1, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner<2, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<4, 16384><<<4, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 8192: {
                ct_inv_ntt_inner<1, 8192><<<8192 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<2, 8192><<<2, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 4096: {
                ct_inv_ntt_inner_single<2, 4096> <<<2, 1024, 2048 * sizeof(uint64_t)>>>(operand, tables);
                ct_inv_ntt_inner<1, 4096> <<<4096 / 1024 / 2, 1024>>>(operand, tables);
                g_multiply_inv_degree_ntt_tables<<<4, 1024>>>(operand, tables);
                g_mod_using_ntt_tables<<<4, 1024>>>(operand, tables);
                break;
            }
            case 2048: {
                ct_inv_ntt_inner_single<1, 2048> <<<1, 1024, 2048 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            default:
                throw std::invalid_argument("not support");
        }
        CHECK(cudaGetLastError());
    }

    void g_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables,
                                 cudaStream_t &stream) {
        switch (coeff_count) {
            case 32768: {
                ct_ntt_inner<1, 32768><<<32768 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner<2, 32768><<<32768 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner<4, 32768><<<32768 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner_single<8, 32768><<<8, 1024, 4096 * sizeof(uint64_t), stream>>>(operand, tables);
                break;
            }
            case 16384: {
                ct_ntt_inner<1, 16384><<<16384 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner<2, 16384><<<16384 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner_single<4, 16384><<<4, 1024, 4096 * sizeof(uint64_t), stream>>>(operand, tables);
                break;
            }
            case 8192: {
                ct_ntt_inner<1, 8192><<<8192 / 1024 / 2, 1024, 0, stream>>>(operand, tables);
                ct_ntt_inner_single<2, 8192><<<2, 1024, 4096 * sizeof(uint64_t), stream>>>(operand, tables);
                break;
            }
            case 4096: {
                ct_ntt_inner_single<1, 4096> <<<1, 1024, 4096 * sizeof(uint64_t), stream>>>(operand, tables);
                break;
            }
            case 2048: {
                ct_ntt_inner_single<1, 2048> <<<1, 1024, 2048 * sizeof(uint64_t), stream>>>(operand, tables);
                break;
            }
            default:
                throw std::invalid_argument("not support");
        }
        CHECK(cudaGetLastError());
    }

    void g_inv_ntt_negacyclic_harvey(uint64_t *operand, size_t coeff_count, const util::NTTTables &tables,
                                     cudaStream_t &stream) {
        switch (coeff_count) {
            case 32768: {
                ct_inv_ntt_inner<1, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);//一半执行就行
                ct_inv_ntt_inner<2, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner<4, 32768><<<32768 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<8, 32768><<<8, 1024, 4096 * sizeof(uint64_t)>>>(operand,
                                                                                        tables);//4096 * sizeof(uint64_t)动态分配的共享内存大小
                break;
            }
            case 16384: {
                ct_inv_ntt_inner<1, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner<2, 16384><<<16384 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<4, 16384><<<4, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 8192: {
                ct_inv_ntt_inner<1, 8192><<<8192 / 1024 / 2, 1024>>>(operand, tables);
                ct_inv_ntt_inner_single<2, 8192><<<2, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 4096: {
                ct_inv_ntt_inner_single<1, 4096> <<<1, 1024, 4096 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            case 2048: {
                ct_inv_ntt_inner_single<1, 2048> <<<1, 1024, 2048 * sizeof(uint64_t)>>>(operand, tables);
                break;
            }
            default:
                throw std::invalid_argument("not support");
        }
        CHECK(cudaGetLastError());
    }

    __device__ inline constexpr int d_hamming_weight(unsigned char value) {
        int t = static_cast<int>(value);
        t -= (t >> 1) & 0x55;
        t = (t & 0x33) + ((t >> 2) & 0x33);
        return (t + (t >> 4)) & 0x0F;
    }

    __global__
    void g_sample_poly_cbd(const Modulus *coeff_modulus, size_t coeff_modulus_size, size_t coeff_count,
                           uint64_t *destination) {

        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        auto ptr = destination + tid;
        auto c_ptr = reinterpret_cast<unsigned char *>(ptr);
        c_ptr[2] &= 0x1F;
        c_ptr[5] &= 0x1F;
        int32_t noise = d_hamming_weight(c_ptr[0]) + d_hamming_weight(c_ptr[1]) + d_hamming_weight(c_ptr[2]) -
                        d_hamming_weight(c_ptr[3]) - d_hamming_weight(c_ptr[4]) - d_hamming_weight(c_ptr[5]);
        auto flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
        for (uint i = 0; i < coeff_modulus_size; ++i) {
            *(ptr + i * coeff_count) = static_cast<uint64_t>(noise) + (flag & (*(coeff_modulus + i)).value());
        }
    }

    void sample_poly_cbd(
            util::RandomGenerator *random_generator, const Modulus *coeff_modulus, size_t coeff_modulus_size,
            size_t coeff_count, uint64_t *destination) {

        random_generator->generate(destination, coeff_count);

        g_sample_poly_cbd<<<coeff_count / 128, 128>>>(coeff_modulus, coeff_modulus_size, coeff_count, destination);

    }

    void sample_poly_cbd(
            util::RandomGenerator *random_generator, const Modulus *coeff_modulus, size_t coeff_modulus_size,
            size_t coeff_count, uint64_t *destination, cudaStream_t &stream) {

        random_generator->generate(destination, coeff_count, stream);

        g_sample_poly_cbd<<<coeff_count / 1024, 1024, 0, stream>>>(coeff_modulus, coeff_modulus_size, coeff_count,
                                                                   destination);

    }

    __global__
    void g_add_negate_poly_coeffmod(
            const uint64_t *operand1, const uint64_t *operand2, const uint64_t *operand3, const uint64_t modulus_value,
            uint64_t *result) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        std::uint64_t sum = operand1[tid] + operand2[tid];
        auto coeff = SIGMA_COND_SELECT(sum >= modulus_value, sum - modulus_value, sum);
        std::int64_t non_zero = (coeff != 0);
        coeff = (modulus_value - coeff) & static_cast<std::uint64_t>(-non_zero);
        sum = coeff + operand3[tid];
        result[tid] = SIGMA_COND_SELECT(sum >= modulus_value, sum - modulus_value, sum);
    }

    void add_negate_add_poly_coeffmod(
            const uint64_t *operand1, const uint64_t *operand2, const uint64_t *operand3, std::size_t coeff_count,
            uint64_t modulus_value, uint64_t *result) {

        g_add_negate_poly_coeffmod<<<coeff_count / 128, 128>>>(operand1, operand2, operand3, modulus_value, result);

    }

    void add_negate_add_poly_coeffmod(
            const uint64_t *operand1, const uint64_t *operand2, const uint64_t *operand3, std::size_t coeff_count,
            uint64_t modulus_value, uint64_t *result, cudaStream_t &stream) {

        g_add_negate_poly_coeffmod<<<coeff_count / 128, 128, 0, stream>>>(operand1, operand2, operand3, modulus_value,
                                                                          result);
    }

    __global__
    void g_add_poly_coeffmod(//多项式加法，对其中系数进行并行
            const uint64_t *operand1, const uint64_t *operand2, const uint64_t modulus_value, uint64_t *result) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        auto sum = operand1[tid] + operand2[tid];
        result[tid] = SIGMA_COND_SELECT(sum >= modulus_value, sum - modulus_value, sum);
    }

    void add_poly_coeffmod(//
            const uint64_t *operand1, const uint64_t *operand2, size_t size, size_t coeff_modulus_size,
            std::size_t coeff_count, uint64_t modulus_value, uint64_t *result) {
        auto total_size = size * coeff_modulus_size * coeff_count;
        g_add_poly_coeffmod<<<total_size / 128, 128>>>(operand1, operand2, modulus_value, result);
    }

    __global__ void g_modulo_poly_coeffs(
            uint64_t* operand,
            std::size_t coeff_count,
            const Modulus &modulus,
            uint64_t* result
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;

        result[tid] = d_barrett_reduce_64(operand[tid], modulus);

    }

    void d_modulo_poly_coeffs(
            uint64_t* operand,
            std::size_t coeff_count,
            const Modulus &modulus,
            uint64_t* result
    ) {
        size_t blocknum = ceil(coeff_count / 1024);
        g_modulo_poly_coeffs<<<blocknum, 1024>>>(operand, coeff_count, modulus, result);
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

        uint64_t index_raw = shift + tid;
        uint64_t index = index_raw & (static_cast<uint64_t>(coeff_count) - 1);
        for (int i = 0; i < coeff_mod_count; i++) {
            const uint64_t modulusValue = (modulus[i]).value();
            size_t id = i * coeff_count + tid;
            size_t rid = i * coeff_count + index;

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
    }

    __global__ void g_mod_using_ntt_tables(
            uint64_t* operand,
            size_t poly_size, size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const util::NTTTables &ntt_table)
    {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        const Modulus& modulus = ntt_table.modulus();
        uint64_t modulus_value = modulus.value();
        uint64_t twice_modulus_value = modulus_value << 1;
        if (operand[tid] >= twice_modulus_value) operand[tid] -= twice_modulus_value;
        if (operand[tid] >= modulus_value) operand[tid] -= modulus_value;
    }

    void d_mod_using_ntt_tables(
            uint64_t* operand,
            size_t poly_size, size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const util::NTTTables &ntt_table)
    {
        size_t block_count = ceil(poly_modulus_degree / 256.0);
        g_mod_using_ntt_tables<<<block_count, 256>>>(
                operand, poly_size, coeff_modulus_size,
                poly_modulus_degree, ntt_table);
    }

    __global__ void g_ntt_transferfrom_rev_layered(
            size_t L,
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const util::NTTTables &ntt_table,
            bool use_inv_root_powers
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
        if(tid >= 1 << (poly_modulus_degree_power - 1)){
            return;
        }
        size_t m = 1 << (poly_modulus_degree_power - 1 - L);//2048
        size_t gap_power = L;
        size_t gap = 1 << gap_power;
        size_t rid = (1 << poly_modulus_degree_power) - (m << 1) + 1 + (tid >> gap_power);
        size_t coeff_index = ((tid >> gap_power) << (gap_power + 1)) + (tid & (gap - 1));
        uint64_t u, v;
        const Modulus& modulus = ntt_table.modulus();
        uint64_t two_times_modulus = modulus.value() << 1;
        const MultiplyUIntModOperand *roots = ntt_table.get_from_device_inv_root_powers();
        MultiplyUIntModOperand r = roots[rid];
        uint64_t* x = operand + coeff_index;
        uint64_t* y = x + gap;
        u = *x;
        v = *y;
        *x = (u + v > two_times_modulus) ? (u + v - two_times_modulus) : (u + v);
        *y = d_multiply_uint_mod_lazy(u + two_times_modulus - v, r, modulus);
    }

    void d_ntt_transfer_from_rev_layered(
            size_t L,
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const util::NTTTables &ntt_table,
            bool use_inv_root_powers
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        size_t block_count = ceil(n / 256.0);
        g_ntt_transferfrom_rev_layered<<<block_count, 256>>>(
                L, operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_table,
                use_inv_root_powers
        );
    }

    __global__ void g_multiply_inv_degree_ntt_tables(
            uint64_t* poly_array,
            size_t poly_size, size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const util::NTTTables &ntt_table
    ) {
        auto tid = blockDim.x * blockIdx.x + threadIdx.x;
            const Modulus& modulus = ntt_table.modulus();
            MultiplyUIntModOperand scalar = ntt_table.inv_degree_modulo();
            poly_array[tid] = d_multiply_uint_mod_lazy(poly_array[tid], scalar, modulus);
    }

    void d_ntt_transfer_from_rev(
            uint64_t *operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const util::NTTTables &ntt_tables,
            bool use_inv_root_powers
    ) {
        std::size_t n = size_t(1) << poly_modulus_degree_power;
        std::size_t m = n >> 1;
        std::size_t L = 0;
        for(; m >= 1; m >>= 1) {
            d_ntt_transfer_from_rev_layered(
                    L, operand,
                    poly_size, coeff_modulus_size,
                    poly_modulus_degree_power, ntt_tables,
                    use_inv_root_powers);
            L++;
        }
        size_t block_count = ceil(n / 256.0);
        g_multiply_inv_degree_ntt_tables<<<block_count, 256>>>(
                operand, poly_size, coeff_modulus_size, n, ntt_tables
        );
    }

    void d_inverse_ntt_negacyclic_harvey_lazy(
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const util::NTTTables &ntt_tables)
    {
        d_ntt_transfer_from_rev(operand, poly_size, coeff_modulus_size,
                            poly_modulus_degree_power, ntt_tables, true);
    }

    void d_inverse_ntt_negacyclic_harvey(
            uint64_t* operand,
            size_t poly_size,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree_power,
            const util::NTTTables &ntt_tables)
    {
        d_inverse_ntt_negacyclic_harvey_lazy(
                operand, poly_size, coeff_modulus_size,
                poly_modulus_degree_power, ntt_tables
        );
        d_mod_using_ntt_tables(
                operand, poly_size, coeff_modulus_size,
                1 << poly_modulus_degree_power, ntt_tables);
        CHECK(cudaGetLastError());
    }
}