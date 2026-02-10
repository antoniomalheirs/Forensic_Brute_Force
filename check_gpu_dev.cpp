
#include <iostream>
// Try to include CUDA
#if defined(CHECK_CUDA)
#include <cuda_runtime.h>
#endif
// Try to include OpenCL
#if defined(CHECK_OPENCL)
#include <CL/cl.h>
#endif

int main() {
  std::cout << "Headers found!" << std::endl;
  return 0;
}
