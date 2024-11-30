cmake_minimum_required(VERSION 3.10)

# Project name and language
project(CasRSA_CL)

# Set the OpenCL include path and library path
find_package(OpenCL REQUIRED)

# Include OpenCL headers
include_directories(${OpenCL_INCLUDE_DIRS})

# Specify the source files
set(SOURCES CasRSA_CL.cpp)

# Add the executable target
add_executable(CasRSA_CL ${SOURCES})

# Link the OpenCL library
target_link_libraries(CasRSA_CL ${OpenCL_LIBRARIES})

# Add definitions for OpenCL
target_compile_definitions(CasRSA_CL PRIVATE CL_TARGET_OPENCL_VERSION=120)

# Copy the kernel file to the output directory without cyclic dependency
set(KERNEL_FILE kernel_rsa.cl)
add_custom_command(
    TARGET CasRSA_CL POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_SOURCE_DIR}/${KERNEL_FILE} $<TARGET_FILE_DIR:CasRSA_CL>
)
