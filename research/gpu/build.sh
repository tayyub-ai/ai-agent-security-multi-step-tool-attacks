set +e
echo "cmake: $(cmake --version 2>&1 | head -1)"; echo "gcc: $(gcc --version 2>&1 | head -1)"; echo "ninja: $(ninja --version 2>&1)"
which cmake >/dev/null 2>&1 || { echo "installing cmake/build tools"; apt-get update -q >/dev/null 2>&1; apt-get install -y -q cmake build-essential ninja-build >/dev/null 2>&1; }
echo "cmake now: $(cmake --version 2>&1 | head -1)"
pip3 uninstall -y llama-cpp-python >/dev/null 2>&1
echo "=== building llama-cpp-python from source (CUDA, native CPU) ==="
export CMAKE_ARGS="-DGGML_CUDA=on -DGGML_NATIVE=on -DGGML_AVX512=OFF -DCMAKE_CUDA_ARCHITECTURES=89"
export FORCE_CMAKE=1
nohup pip3 install --no-binary :all: --no-cache-dir "llama-cpp-python==0.3.35" > /root/logs/build.log 2>&1 &
echo "build pid $!"
sleep 5; tail -3 /root/logs/build.log
