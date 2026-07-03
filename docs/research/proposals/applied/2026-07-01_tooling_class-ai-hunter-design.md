# PROPOSAL (proposal) for docs/knowledge/class-ai-hunter-design.md — tooling 2026-07-01
_Review and apply manually; not auto-merged into the KB._

## Nuclei AI/LLM panel sweep (2026-07-01)

New in nuclei-templates v10.4.3 (May 2026): 20+ AI/ML infrastructure panel detection templates.
These are high dup-resistance targets — companies deploy AI infra without security review and the crowd isn't scanning for them.

**Target panels now detectable:**
AgentGPT, AnythingLLM, AstrBot, ClearML, ChromaDB (+ unauthenticated API), Flowise, H2O Wave, KoboldAI, Langflow, llama.cpp, Marqo, OpenHands, SillyTavern, Stable Diffusion WebUI, Weights & Biases, Xinference, Chainlit, ComfyUI, Marimo

**Add to the pipeline:**
```bash
nuclei -update-templates  # ensure v10.4.3+
nuclei -tags panel -l <in-scope-hosts.txt> -o ai_panels_$(date +%Y%m%d).json
