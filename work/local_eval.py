"""Mirror the gateway: generation (attack.run drives live env) -> replay+score."""
import sys, time, importlib.util
sys.path.insert(0, "/Users/tayyab/Downloads/Ai Security - Kaggle Challenge/comp")
sys.path.insert(0, "/Users/tayyab/Downloads/Ai Security - Kaggle Challenge/work")
from pathlib import Path
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.env.opaque import _OpaqueAttackEnv
from aicomp_sdk.guardrails.optimal import Guardrail
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.scoring import score_attack
from aicomp_sdk.attacks import AttackRunConfig
from mock_llm import MockLLMAgent

FIX = Path("/Users/tayyab/Downloads/Ai Security - Kaggle Challenge/comp/aicomp_sdk/fixtures")

def load_attack():
    spec = importlib.util.spec_from_file_location("user_attack",
        "/Users/tayyab/Downloads/Ai Security - Kaggle Challenge/work/attack.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.AttackAlgorithm

def make_env(agent_kw):
    return SandboxEnv(seed=123, fixtures_dir=FIX, agent=MockLLMAgent(**agent_kw), guardrail=Guardrail())

def run_once(agent_kw, gen_budget=30.0, replay_budget=60.0, max_replay=2000, label=""):
    Attack = load_attack()
    # ---- generation: attacker drives an opaque env with the live model ----
    gen_env = _OpaqueAttackEnv(make_env(agent_kw))
    gen_env.reset()
    t0=time.monotonic()
    cands = Attack(config={}).run(gen_env, AttackRunConfig(time_budget_s=gen_budget))
    gen_t = time.monotonic()-t0
    # ---- replay + score (fresh env per candidate) ----
    findings=[]; deadline=time.monotonic()+replay_budget; replayed=0; timed_out=False; hops_used=0
    for cand in cands[:max_replay]:
        if time.monotonic()>=deadline: timed_out=True; break
        env = make_env(agent_kw); env.reset()
        for msg in cand.user_messages:
            if time.monotonic()>=deadline: timed_out=True; break
            r=env.interact(msg, max_tool_hops=8); hops_used+=r.agent_turns
        replayed+=1
        tr=env.export_trace_dict(); preds=eval_predicates(tr)
        if not preds: continue
        findings.append({"predicates":preds,
                         "score_cell_signature":cell_signature(tr["tool_events"])})
    score=score_attack(findings)
    n_exfil=sum(1 for f in findings for p in f["predicates"] if p["predicate"]=="EXFILTRATION")
    n_cd=sum(1 for f in findings for p in f["predicates"] if p["predicate"]=="CONFUSED_DEPUTY")
    print(f"[{label}] cands={len(cands)} gen={gen_t:.1f}s replayed={replayed} "
          f"validated={len(findings)} EXFIL={n_exfil} CD={n_cd} "
          f"hops={hops_used} timeout={timed_out} -> SCORE={score:.2f}")
    return score

if __name__ == "__main__":
    print("Simulated scoring (replay_budget bounds how many candidates get scored):")
    run_once(dict(comply_rate=1.0, max_posts_per_msg=8, do_email=True), replay_budget=20, label="gpt_oss-ideal ")
    run_once(dict(comply_rate=0.6, max_posts_per_msg=8, do_email=True), replay_budget=20, label="gemma-partial ")
    run_once(dict(comply_rate=0.3, max_posts_per_msg=3, do_email=False), replay_budget=20, label="cautious-model")
    run_once(dict(comply_rate=1.0, max_posts_per_msg=8, do_email=True), replay_budget=120, label="ideal-bigbudget")
