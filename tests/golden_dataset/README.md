# Golden Dataset — LLM Quality Evaluation

This directory contains the reference dataset used to measure the quality of
the LLM Normalizer module (precision, recall, F1 on STIX extraction).

**Populated during Phase 3 (P3-01).**

## Structure

```
golden_dataset/
├── README.md            # This file
├── articles/            # Raw CTI articles (text files, one per article)
│   ├── 001_apt28_campaign.txt
│   ├── 002_ransomware_analysis.txt
│   └── ...
├── expected/            # Manually annotated expected STIX output
│   ├── 001_apt28_campaign.json
│   ├── 002_ransomware_analysis.json
│   └── ...
└── test_llm_quality.py  # Pytest test that runs evaluation and reports metrics
```

## Annotation guidelines

Each `expected/*.json` file must contain:

```json
{
  "source_file": "001_apt28_campaign.txt",
  "annotated_by": "<name>",
  "annotated_at": "2026-XX-XX",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = '198.51.100.1']",
      "pattern_type": "stix",
      "name": "APT28 C2 IP"
    }
  ]
}
```

**Rules for annotation:**
- Only include entities **explicitly stated** in the text — no inference.
- For IoCs: include the exact value as it appears (do not normalise case for domains).
- For Threat Actors: include the primary name and any aliases mentioned.
- For Attack Patterns: include the MITRE ATT&CK ID if mentioned or clearly implied.
- For Relationships: only annotate those explicitly stated in the text.

## Target composition (50 articles)

| Category | Count | Examples |
|---|---|---|
| Vendor PDF reports | 15 | Mandiant, CrowdStrike, ESET, Recorded Future |
| Security blogs | 20 | Krebs, SANS ISC, BleepingComputer, The DFIR Report |
| MISP bulletins | 10 | CIRCL feeds, national CERT advisories |
| Non-English articles | 5 | French ANSSI, German BSI, Russian Kaspersky |

## Quality targets

| Metric | Target |
|---|---|
| IoC Precision | > 0.85 |
| IoC Recall | > 0.75 |
| IoC F1-score | > 0.80 |
| JSON valid (no retry) | > 90% |
| Source URL match | > 95% |
