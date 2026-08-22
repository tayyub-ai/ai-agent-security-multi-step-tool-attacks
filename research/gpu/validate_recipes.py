"""GPU: does the REAL model comply with each v7 recipe, and which predicates fire
under the PUBLIC guardrail and the MOCK PRIVATE guardrail? Prunes non-complying
recipes and measures diversity (unique cells)."""
import os,sys,time,argparse
sys.path.insert(0,"/root"); sys.path.insert(0,"/root/comp")
os.environ.setdefault("GPT_OSS_MODEL_PATH","/root/models/gpt-oss-20b-Q4_K_M.gguf")
os.environ.setdefault("GEMMA_MODEL_PATH","/root/models/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf")
from pathlib import Path
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.guardrails.optimal import Guardrail as PubG
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.core.cells import cell_signature
from kaggle_evaluation.jed_attack_134815 import gpt_oss_model_server, gemma_model_server
from kaggle_evaluation.jed_attack_134815.gguf_model_server import GgufModelServer
import mockpriv
FIX=Path("/root/comp/aicomp_sdk/fixtures")
ap=argparse.ArgumentParser(); ap.add_argument("--model",default="gpt_oss"); A=ap.parse_args()
spec=gpt_oss_model_server.SPEC if A.model=="gpt_oss" else gemma_model_server.SPEC
srv=GgufModelServer(spec); srv.load_model(); print(f"[load] {A.model}",flush=True)
import importlib.util
s=importlib.util.spec_from_file_location("ua","/root/submission/attack.py"); ua=importlib.util.module_from_spec(s); s.loader.exec_module(ua)
def run(msgs, guard):
    env=SandboxEnv(seed=123,fixtures_dir=FIX,agent=srv._load_agent(),guardrail=guard,max_tool_hops=8); env.reset()
    for m in msgs: env.interact(m,max_tool_hops=8)
    tr=env.export_trace_dict()
    tools=[(e['name'],'ok' if e['ok'] else 'x',e.get('source')) for e in tr['tool_events']]
    pub=[(p['predicate'],p['severity']) for p in eval_predicates(tr)]
    return tools, tr
def test(name, recipe_fn, n=3):
    for guardname,guard in (("PUBLIC",PubG()),("PRIVATE",mockpriv.Guardrail())):
        firecnt=0; cells=set(); preds={}
        for i in range(1,n+1):
            tools,tr=run(recipe_fn(i), guard)
            pr=eval_predicates(tr)
            if pr: firecnt+=1; cells.add(cell_signature(tr["tool_events"])["hash"])
            for p in pr: preds[p['predicate']]=preds.get(p['predicate'],0)+1
        ex=run(recipe_fn(99),guard)[0][:4]
        print(f"[{A.model}][{name}][{guardname}] fired={firecnt}/{n} cells={len(cells)} preds={preds} sample_tools={ex}",flush=True)
print("=== recipe compliance + firing on REAL model ===",flush=True)
test("exfil_forge", ua._r_exfil_forge)
test("confused_deputy", ua._r_confused_deputy)
test("web_post (UNTRUSTED)", ua._r_web_post)
test("email_post (UNTRUSTED)", ua._r_email_post)
test("web_shell (UNTRUSTED)", ua._r_web_shell)
test("web_forward (UNTRUSTED)", ua._r_web_forward)
