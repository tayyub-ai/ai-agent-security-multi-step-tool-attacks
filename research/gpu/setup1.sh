set -e
cd /root
echo "=== pip deps ==="
pip3 install -q --no-input huggingface_hub hf_transfer pydantic "gymnasium<1,>=0.29" numpy 2>&1 | tail -3
mkdir -p /root/models /root/logs
echo "=== start GGUF downloads in background ==="
export HF_HUB_ENABLE_HF_TRANSFER=1
cat > /root/dl.py <<'PY'
import os
os.environ["HF_HUB_ENABLE_HF_TRANSFER"]="1"
from huggingface_hub import hf_hub_download
jobs=[("unsloth/gpt-oss-20b-GGUF","gpt-oss-20b-Q4_K_M.gguf"),
      ("unsloth/gemma-4-26B-A4B-it-GGUF","gemma-4-26B-A4B-it-UD-Q4_K_M.gguf")]
for repo,fn in jobs:
    print("DL",repo,fn,flush=True)
    p=hf_hub_download(repo_id=repo,filename=fn,local_dir="/root/models",local_dir_use_symlinks=False)
    print("DONE",p,flush=True)
print("ALL_DONE",flush=True)
PY
setsid nohup python3 /root/dl.py > /root/logs/dl.log 2>&1 &
echo "download pid $!"
sleep 4
echo "=== dl.log so far ==="; tail -5 /root/logs/dl.log
