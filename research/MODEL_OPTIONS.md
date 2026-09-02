# Model-Assisted Research Options

Last checked: 2026-08-26

## Boundary

Codex credits pay for Codex/ChatGPT work. They do not pay DeepSeek, Kimi, Qwen,
MiniMax, GLM, OpenRouter, cloud GPU, or electricity. GitHub repositories provide
code, weights, and deployment instructions; they do not provide inference compute.

The competition permits LLM-assisted candidate generation and freely/publicly
available pretrained models. The submitted Kaggle notebook must run with internet
disabled, so remote models belong in the research loop, not in `attack.py`.

## Priority order

| Priority | Option | Where it runs | This machine | Best use | Status |
|---|---|---|---|---|---|
| P0 | Exact `gpt-oss-20b` target | Local or rented GPU | Borderline at 16 GB; close other apps | Prompt/tool-compliance oracle | Needs runtime + weights |
| P0 | Exact Gemma 4 target | Rented >=24 GB GPU | No | Transfer oracle | Existing GPU scripts ready |
| P1 | DeepSeek V4 Pro API | DeepSeek | Yes, remote | Deep reasoning, gap analysis, critique | Needs `DEEPSEEK_API_KEY` |
| P1 | Kimi K2.6 API | Moonshot | Yes, remote | Long-context repo audit, agentic ideas | Needs `MOONSHOT_API_KEY` |
| P1 | Qwen3-Coder-Next / 30B-A3B | Hosted or larger machine | No practical local fit | Code and harness review | Generic endpoint supported |
| P1 | MiniMax M2.5 | Hosted or large GPU | No | Independent agent/tool-use critique | Generic endpoint supported |
| P1 | GLM agent/coding family | Hosted or large GPU | No | Independent guard-hypothesis critique | Generic endpoint supported |
| P2 | DeepSeek-R1-Distill-Qwen-7B | Local quantized | Yes | Cheap reasoning diversity | Config ready |
| P2 | Qwen2.5-Coder-7B | Local quantized | Yes | Cheap code/experiment review | Config ready |
| P2 | Gemma 3/4 small quantized | Local quantized | Yes for small variants | Gemma-family prompt screening | Add after exact target tests |
| P3 | Llama/Mistral/other 7B-12B scouts | Local quantized | Usually | Diversity only | Add only after P0-P2 |

The exact target models outrank every frontier panel model because leaderboard
value depends on their deterministic tool behavior, not general benchmark quality.

## Named options clarified

- **DeepSeek:** the full open checkpoints are hundreds of billions of parameters;
  use the official API or rented multi-GPU hardware. The 7B R1 distill is suitable
  for this Mac as a research scout, but it is not behaviorally equivalent to the
  full model.
- **Kimi:** Kimi K2 open weights are a 1T-parameter MoE checkpoint. Kimi K2.6 is
  currently offered through Moonshot's OpenAI-compatible API. It is a remote panel
  model here, not a local one.
- **Mythos:** `mythos-agent/mythos-agent` is a security-agent framework, not a
  frontier foundation model. It could sit above the same APIs, but it adds little
  to this benchmark-specific harness. If "Mythos" meant MythoMax, that is an older
  role-play-oriented merge and is low priority for code/security reasoning.
- **GitHub Models / OpenRouter / other aggregators:** convenient access layers, but
  they use their own quotas or billing. They can be added to the panel with an
  OpenAI-compatible URL and model ID.

## Research roles

Do not ask every model the same vague question. Use independent roles:

1. Gap analyst: enumerate mechanism-level strategy families missing from the log.
2. Prompt mutator: produce compact variants for one known mechanism.
3. Implementation auditor: find score/sec, timeout, serialization, and artifact bugs.
4. Private-transfer critic: attack the P1/P2/P3 guard hypotheses.
5. Target oracle: run only the highest-value proposals against exact gpt-oss/Gemma.

Every proposal must include a falsification test. Model votes are not evidence.

## Panel tool

List configured providers:

```bash
python3 research/model_panel.py --list
```

Preview exactly what would be sent, without using a key or network:

```bash
python3 research/model_panel.py \
  --provider kimi-k2-6 \
  --task gap-analysis \
  --dry-run
```

Run one remote provider after exporting its key:

```bash
export MOONSHOT_API_KEY='...'
python3 research/model_panel.py \
  --provider kimi-k2-6 \
  --task gap-analysis \
  --allow-remote
```

The explicit `--allow-remote` flag prevents accidental source upload. Results go
to the gitignored `research/model_panel_results/` directory and never include the
API key or provider URL.

To add Qwen, MiniMax, GLM, OpenRouter, a rented vLLM server, LM Studio, or another
provider, copy `research/model_panel.example.json` to the gitignored
`research/model_panel.local.json` and add its OpenAI-compatible chat-completions
URL, model ID, and API-key environment-variable name.

## Inputs needed to continue

No secret should be pasted into chat or committed to the repo. The next live step
needs one of these access paths:

- Export `MOONSHOT_API_KEY` or `DEEPSEEK_API_KEY` in the terminal for a hosted
  panel run. Starting with one provider is enough; compare a second only when the
  first produces hypotheses worth cross-checking.
- Approve roughly 15 GB of local model/runtime downloads for `gpt-oss-20b` on this
  16 GB Mac. This is at the memory limit and may be slow, but it is the exact model
  family and therefore more valuable than a generic local scout.
- Provide a rented Linux NVIDIA host (SSH details entered locally, not committed)
  with at least 24 GB VRAM for the existing two-target GGUF oracle. This is the
  strongest experiment path.
- Configure Kaggle authentication locally so exact notebook pushes, reruns, and
  score logging can be automated. The Kaggle package exists, but
  `~/.kaggle/kaggle.json` is currently missing.

Before paying for several APIs, set a small research budget and run one task per
provider. The initial useful ceiling is four calls: gap analysis, implementation
audit, prompt mutation, and private-transfer critique.

## Sources

- [Kaggle competition overview and code requirements](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks/overview/abstract)
- [OpenAI gpt-oss repository](https://github.com/openai/gpt-oss)
- [DeepSeek R1 repository and distill sizes](https://github.com/deepseek-ai/DeepSeek-R1)
- [DeepSeek API quick start](https://api-docs.deepseek.com/quick_start/pricing-details-cny/)
- [Kimi K2 open-weight repository](https://github.com/MoonshotAI/Kimi-K2)
- [Kimi API overview](https://platform.kimi.ai/docs/api/overview)
- [Kimi model list](https://platform.kimi.ai/docs/models)
- [Qwen3-Coder repository](https://github.com/QwenLM/Qwen3-Coder)
- [MiniMax M2.5 repository](https://github.com/MiniMax-AI/MiniMax-M2.5)
- [GLM agent/coding models](https://github.com/zai-org/GLM-4.5)
