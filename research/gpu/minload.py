import sys, time
from llama_cpp import Llama
path=sys.argv[1]; ngl=int(sys.argv[2])
print(f"loading {path} n_gpu_layers={ngl}", flush=True)
t=time.time()
llm=Llama(model_path=path, n_gpu_layers=ngl, n_ctx=2048, verbose=False)
print(f"LOADED in {time.time()-t:.1f}s", flush=True)
out=llm.create_chat_completion(messages=[{"role":"user","content":"Say the single word: ping"}], max_tokens=8, temperature=0.0)
print("GEN:", repr(out["choices"][0]["message"]["content"])[:200], flush=True)
