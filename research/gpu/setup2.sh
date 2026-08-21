set +e
echo "=== try prebuilt cu124 wheel ==="
pip3 install -q --no-input llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124 2>&1 | tail -4
python3 -c "import llama_cpp; print('WHEEL_OK', llama_cpp.__version__)" 2>&1 | tail -1
