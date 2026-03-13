# LLM Benchmark — CTI Aggregator

Record benchmark results here after running `make benchmark-llm` (P0-03).
This file is committed to track performance across model changes.

## Decision log

| Date | Model | Hardware | Decision | Rationale |
|---|---|---|---|---|
| _to fill_ | llama3.3:70b-instruct-q4_K_M | A100 80GB | _pending_ | _pending_ |

---

## Run: [DATE] — [MODEL]

**Hardware**: NVIDIA A100 80 GB VRAM  
**Quantisation**: Q4_K_M  
**VRAM used**: ___ GB / 80 GB

### Latency

| Chunk size (tokens) | p50 (s) | p95 (s) | p99 (s) |
|---|---|---|---|
| 1 000 | | | |
| 2 000 | | | |
| 3 000 | | | |

**Throughput**: ___ tokens/s

### Quality (10-article spot check)

| Metric | Value | Target |
|---|---|---|
| JSON valid on first try | ___ % | > 90% |
| JSON valid after retry | ___ % | > 98% |
| IoC extraction plausible | ___ / 10 | ≥ 8/10 |
| Hallucinated sources (x_cti_source_url mismatch) | ___ % | < 5% |

### End-to-end latency estimate

With ___ chunks/document (avg) and ___ s/chunk:  
**Estimated pipeline latency**: ___ min (target: < 15 min)

### Decision

- [ ] Model accepted as primary
- [ ] Model rejected — using fallback (reason: ___)
- [ ] Further tuning required (see notes below)

**Notes**:

---

## Fallback model: mistral:7b-instruct-q4_K_M

To be benchmarked only if the primary model fails the latency or quality bar.
