import os, sys, time, math, argparse, importlib.util, statistics
sys.path.insert(0,"/root")
sys.path.insert(0,"/root/comp")
os.environ.setdefault("GPT_OSS_MODEL_PATH","/root/models/gpt-oss-20b-Q4_K_M.gguf")
os.environ.setdefault("GEMMA_MODEL_PATH","/root/models/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf")
from pathlib import Path
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.guardrails.optimal import Guardrail
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.scoring import score_attack
from aicomp_sdk.attacks import AttackRunConfig
from kaggle_evaluation.jed_attack_134815 import gpt_oss_model_server, gemma_model_server
from kaggle_evaluation.jed_attack_134815.gguf_model_server import GgufModelServer
FIX=Path("/root/comp/aicomp_sdk/fixtures")

ap=argparse.ArgumentParser()
ap.add_argument("--model",default="gemma")
ap.add_argument("--attack",default="/root/attack_v2.py")
ap.add_argument("--genbudget",type=float,default=120.0)
ap.add_argument("--replaybudget",type=float,default=180.0)
a=ap.parse_args()

spec=gpt_oss_model_server.SPEC if a.model=="gpt_oss" else gemma_model_server.SPEC
srv=GgufModelServer(spec); t=time.time(); srv.load_model(); print(f"[load] {a.model} {time.time()-t:.1f}s",flush=True)

# token counter: patch the underlying llm.create_chat_completion
TOK=[]
try:
    agent0=srv._load_agent()
    be=getattr(agent0,"_backend",None) or getattr(agent0,"backend",None)
    llm=getattr(be,"llm",None)
    if llm is not None:
        orig=llm.create_chat_completion
        def wrapped(*args,**kw):
            out=orig(*args,**kw)
            try: TOK.append(out["usage"]["completion_tokens"])
            except Exception: pass
            return out
        llm.create_chat_completion=wrapped
        print("[tok] patched",flush=True)
except Exception as e:
    print("[tok] patch failed",e,flush=True)

def new_env(): return SandboxEnv(seed=123,fixtures_dir=FIX,agent=srv._load_agent(),guardrail=Guardrail(),max_tool_hops=8)

spec2=importlib.util.spec_from_file_location("ua",a.attack); m=importlib.util.module_from_spec(spec2); spec2.loader.exec_module(m)

# GENERATION
gen_env=new_env(); gen_env.reset()
tg=time.time()
cands=m.AttackAlgorithm().run(gen_env, AttackRunConfig(time_budget_s=a.genbudget))
gen_secs=time.time()-tg
sizes=[len(c.user_messages) for c in cands]
print(f"[gen] {len(cands)} candidates, msgs/cand min/med/max={min(sizes)}/{int(statistics.median(sizes))}/{max(sizes)}, total_msgs={sum(sizes)}, gen_secs={gen_secs:.1f}",flush=True)
tok_gen=list(TOK); 
if tok_gen: print(f"[tok] gen posts: n={len(tok_gen)} median_completion_tokens={int(statistics.median(tok_gen))} mean={statistics.mean(tok_gen):.0f}",flush=True)

# REPLAY + SCORE (fresh env per candidate, deadline like gateway)
findings=[]; deadline=time.time()+a.replaybudget; replayed=0; timed=False; posts=0
for c in cands:
    if time.time()>=deadline: timed=True; break
    env=new_env(); env.reset()
    ok=True
    for msg in c.user_messages:
        if time.time()>=deadline: timed=True; ok=False; break
        env.interact(msg,max_tool_hops=8)
    if not ok: break
    tr=env.export_trace_dict(); preds=eval_predicates(tr)
    if preds:
        findings.append({"predicates":preds,"score_cell_signature":cell_signature(tr["tool_events"])})
        posts+=sum(1 for p in preds if p["predicate"]=="EXFILTRATION")
    replayed+=1
score=score_attack(findings)
# measured per-post latency in replay
lat=(a.replaybudget if timed else (time.time()-(deadline-a.replaybudget)))/max(1,posts)
print(f"[replay] replayed={replayed}/{len(cands)} findings={len(findings)} posts={posts} timed_out={timed} row_score={score:.2f}",flush=True)
print(f"[lat] ~{lat:.2f}s/post (replay)",flush=True)
# PROJECT to 9000s replay
med_lat=lat
G=9000*0.90/med_lat
if G<=2000: raw=18*G; C=G
else:
    K=min(32,math.ceil(G/2000)); C=min(2000,math.ceil(G/K)); raw=16*G+2*C
proj=min(1000.0, raw/200.0)
print(f"[PROJECT 9000s] G_posts~{G:.0f} -> row~{proj:.0f}",flush=True)
