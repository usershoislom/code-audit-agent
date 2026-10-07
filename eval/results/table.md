| row | reported | TP | FP | FN | precision | recall | F1 | FP vs SAST | TP lost vs SAST | FPR clean files | pair acc. | P (≥L2) | R (≥L2) | s/kLOC | tok/kLOC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sast_only | 50 | 20 | 30 | 6 | 0.4 | 0.769 | 0.526 | — | - | 0.6 | 0.333 | 0.0 | 0.0 | 2.0 | 0 |
| llm_only_files | not run | | | | | | | | | | | | | | |
| sast_llm_triage | not run | | | | | | | | | | | | | | |
| agent_no_llm | 28 | 25 | 3 | 1 | 0.893 | 0.962 | 0.926 | -90% | 0 | 0.057 | 0.833 | 0.926 | 0.962 | 1.9 | 0 |
| agent_llm_norag | not run | | | | | | | | | | | | | | |
| agent_llm_rag | not run | | | | | | | | | | | | | | |
| agent_full | 28 | 25 | 3 | 1 | 0.893 | 0.962 | 0.926 | -90% | 0 | 0.057 | 0.833 | 0.926 | 0.962 | 36.1 | 0 |
