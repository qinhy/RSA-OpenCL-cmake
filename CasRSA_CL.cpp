#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <CL/cl.h>
#include <ctime>

constexpr size_t MAX_SOURCE_SIZE = 0x100000;
constexpr int MAXDIGITS = 500; // Change as needed
constexpr int PLUS = 1;
constexpr int MINUS = -1;

struct Bignum {
    char digits[MAXDIGITS]{};
    int signbit = PLUS;
    int lastdigit = -1;

    void print() const {
        if (signbit == MINUS) std::cout << "- ";
        for (int i = lastdigit; i >= 0; i--)
            std::cout << static_cast<char>('0' + digits[i]);
        std::cout << "\n";
    }

    void from_int(int s) {
        signbit = (s >= 0) ? PLUS : MINUS;
        std::fill(std::begin(digits), std::end(digits), 0);
        lastdigit = -1;

        int t = std::abs(s);
        while (t > 0) {
            lastdigit++;
            digits[lastdigit] = t % 10;
            t /= 10;
        }
        if (s == 0) lastdigit = 0;
    }

    void from_string(const std::string& num_str) {
        from_int(0);
        for (size_t i = 0; i < num_str.length(); ++i) {
            digits[i] = num_str[num_str.length() - 1 - i] - '0';
        }
        lastdigit = num_str.length() - 1;
    }
};

std::string stradd(const std::string& a, const std::string& b) {
    return a + b;
}

void decrypt_message(cl_context context, cl_command_queue queue, cl_program program,
                 const Bignum &p, const Bignum &q, const Bignum &ciphertext,
                //  Bignum &d,
                int d,
                 Bignum &plaintext) {
    cl_int err;
    
    // Create OpenCL buffers
    cl_mem cl_p = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), (void*)&p, &err);
    cl_mem cl_q = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), (void*)&q, &err);
    cl_mem cl_C = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), (void*)&ciphertext, &err);
    cl_mem cl_result = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(Bignum), nullptr, &err);

    // Create and configure the kernel
    cl_kernel decrypt_kernel = clCreateKernel(program, "rsa_decipher", &err);
    clSetKernelArg(decrypt_kernel, 0, sizeof(cl_mem), &cl_p);
    clSetKernelArg(decrypt_kernel, 1, sizeof(cl_mem), &cl_q);
    clSetKernelArg(decrypt_kernel, 2, sizeof(cl_mem), &cl_C);
    clSetKernelArg(decrypt_kernel, 3, sizeof(cl_mem), &cl_result);
    clSetKernelArg(decrypt_kernel, 4, sizeof(int), &d);
    // clSetKernelArg(decrypt_kernel, 4, sizeof(cl_mem), &d);

    // Execute the kernel
    size_t global_ws = 1, local_ws = 1;
    clEnqueueNDRangeKernel(queue, decrypt_kernel, 1, nullptr, &global_ws, &local_ws, 0, nullptr, nullptr);
    clFinish(queue);

    // Read back the result
    clEnqueueReadBuffer(queue, cl_result, CL_TRUE, 0, sizeof(Bignum), &plaintext, 0, nullptr, nullptr);

    // Cleanup
    clReleaseMemObject(cl_p);
    clReleaseMemObject(cl_q);
    clReleaseMemObject(cl_C);
    clReleaseMemObject(cl_result);
    clReleaseKernel(decrypt_kernel);
}


void encrypt_message(cl_context context, cl_command_queue queue, cl_program program,
                     Bignum &p, Bignum &q, Bignum &M, int e, Bignum &result) {
    cl_int err;

    // Create OpenCL buffers
    cl_mem cl_p = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), &p, &err);
    cl_mem cl_q = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), &q, &err);
    cl_mem cl_M = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(Bignum), &M, &err);
    cl_mem cl_result = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(Bignum), nullptr, &err);

    // Create kernel
    cl_kernel rsa_cypher_kernel = clCreateKernel(program, "rsa_cypher", &err);

    // Set kernel arguments
    clSetKernelArg(rsa_cypher_kernel, 0, sizeof(cl_mem), &cl_p);
    clSetKernelArg(rsa_cypher_kernel, 1, sizeof(cl_mem), &cl_q);
    clSetKernelArg(rsa_cypher_kernel, 2, sizeof(cl_mem), &cl_M);
    clSetKernelArg(rsa_cypher_kernel, 3, sizeof(cl_mem), &cl_result);
    clSetKernelArg(rsa_cypher_kernel, 4, sizeof(int), &e);

    // Execute kernel
    size_t global_ws = 1, local_ws = 1;
    err = clEnqueueNDRangeKernel(queue, rsa_cypher_kernel, 1, nullptr, &global_ws, &local_ws, 0, nullptr, nullptr);
    clFinish(queue);

    // Read back the result
    clEnqueueReadBuffer(queue, cl_result, CL_TRUE, 0, sizeof(Bignum), &result, 0, nullptr, nullptr);

    // Release OpenCL resources
    clReleaseMemObject(cl_p);
    clReleaseMemObject(cl_q);
    clReleaseMemObject(cl_M);
    clReleaseMemObject(cl_result);
    clReleaseKernel(rsa_cypher_kernel);
}


int main(int argc, char* argv[]) {
    std::cout << "CasRSA_CL OpenCL 1.2 implementation of RSA\n"
              << "--------------------------------------\n";

    if (argc != 3) {
        std::cerr << "Usage: ./CasRSA_CL conf_file outfile\n"
                  << "Where the conf_file is a text file that contains: [p] [q] [e] [message]\n";
        return 1;
    }

    std::clock_t c_start = std::clock();

    std::string cl_headers = "#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable\n#define PLUS 1\n#define MINUS -1\n#define MAXDIGITS ";
    cl_headers += std::to_string(MAXDIGITS);

    std::ifstream cl_file("kernel_rsa.cl");
    if (!cl_file) {
        std::cerr << "Error: Kernel file not found.\n";
        return 1;
    }
    std::string source_str((std::istreambuf_iterator<char>(cl_file)),
                           std::istreambuf_iterator<char>());

    std::string append_str = cl_headers + source_str;

    cl_int err;
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;

    err = clGetPlatformIDs(1, &platform, nullptr);
    if (err != CL_SUCCESS) {
        std::cerr << "Error getting platform ID.\n";
        return 1;
    }

    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, nullptr);
    if (err != CL_SUCCESS) {
        std::cerr << "Error getting device ID: " << err << "\n";
        return 1;
    }

    cl_uint numberOfCores;
    clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(numberOfCores), &numberOfCores, nullptr);
    std::cout << "\nThis GPU supports " << numberOfCores << " compute units\n";

    // cl_uint maxThreads;
    // clGetDeviceInfo(device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxThreads), &maxThreads, NULL);
    // printf("\nRunning with %i threads per compute units", maxThreads); //Utilize the maximum number of threads/cu
    
    context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) {
        std::cerr << "Error creating context.\n";
        return 1;
    }

    queue = clCreateCommandQueue(context, device, 0, &err);
    if (err != CL_SUCCESS) {
        std::cerr << "Error creating command queue.\n";
        return 1;
    }

    const char* source_cstr = append_str.c_str();
    size_t length = append_str.size();
    cl_program program = clCreateProgramWithSource(context, 1, &source_cstr, &length, &err);
    if (err != CL_SUCCESS) {
        std::cerr << "Error creating program.\n";
        return 1;
    }

    err = clBuildProgram(program, 1, &device, "-I ./ -cl-std=CL1.2", nullptr, nullptr);
    if (err == CL_BUILD_PROGRAM_FAILURE) {
        std::cerr << "Build Error.\n";
        size_t log_size;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);

        std::vector<char> log(log_size);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::cerr << log.data() << "\n";
    }

    //////////////////////////////////////////////////////////////////////////
    Bignum p, q, M, en_result, de_result, d_big;
    int e,d=503;

    // Read `p`, `q`, `e`, `d`, and `M` from input files
    std::ifstream conf_file(argv[1]);
    if (!conf_file) {
        std::cerr << "Error opening configuration file.\n";
        return 1;
    }

    std::ofstream outfile(argv[2]);
    if (!outfile) {
        std::cerr << "Error opening output file. Check permissions.\n";
        return 1;
    }

    std::string ps, qs, Ms;
    conf_file >> ps >> qs >> e >> Ms;

    M.from_string(Ms);
    p.from_string(ps);
    q.from_string(qs);

    std::cout << "INPUT:\n\tM: ";M.print();
    std::cout << "\tP: ";p.print();
    std::cout << "\tQ: ";q.print();

    
    d_big.from_string("503");
    std::cout << "\tD: ";d_big.print();

    // p, q: Prime factors of the RSA modulus.
    // e: Public key exponent.
    // d: Private key exponent.
    // M: Plaintext message.
    // The program should:

    // Encrypt the message using rsa_cypher.
    // Decrypt the message using rsa_decipher.
    // Verify that the decrypted message matches the original plaintext.

    // Encrypt: rsa_cypher
    encrypt_message(context, queue, program, p, q, M, e, en_result);
    std::cout << "\nEncrypted Result: ";
    en_result.print();
    // Decrypt: rsa_decipher
    decrypt_message(context, queue, program, p, q, en_result, d, de_result);
    std::cout << "\nDecrypted Result: ";
    de_result.print();

    std::clock_t c_stop = std::clock();
    float diff = (static_cast<float>(c_stop - c_start) / CLOCKS_PER_SEC) * 1000;
    std::cout << "\nTime taken: " << diff << " ms\n";

    // en_result.print();
    // for (int i = en_result.lastdigit + 1; i-- > 0;) {
    //     outfile << static_cast<char>(en_result.digits[i] + '0');
    // }

    clReleaseContext(context);
    clReleaseCommandQueue(queue);
    return 0;
}

