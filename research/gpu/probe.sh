set +e
echo "===GUIDE(head)==="; head -40 /etc/vast-agents-guide.md 2>/dev/null
echo "===ENV==="
python3 --version; echo "pip: $(pip3 --version 2>&1 | head -1)"
echo "nvcc: $(nvcc --version 2>/dev/null | tail -1)"
echo "gpu:"; nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
echo "disk:"; df -h / | tail -1
echo "mem: $(free -g | awk '/Mem/{print $2}')GB  cpu: $(nproc)"
python3 -c "import llama_cpp; print('llama_cpp', llama_cpp.__version__)" 2>&1 | tail -1
python3 -c "import huggingface_hub; print('hf_hub', huggingface_hub.__version__)" 2>&1 | tail -1
echo "curl: $(which curl); git: $(which git)"
