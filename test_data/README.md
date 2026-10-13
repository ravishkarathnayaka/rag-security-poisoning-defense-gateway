# Test Corpus & Adversarial Payloads

This directory provides synthetic documents designed to validate the ingestion and runtime defenses of the **RAG Security & Indirect Prompt Injection Defense Gateway**.

## Generating the Corpus

Run the generator script to create sample files inside `test_data/corpus/`:

```bash
python test_data/generate_test_corpus.py
```

## Corpus Manifest & Threat Vector Mapping

| Document Filename | Classification | Primary Attack Vector / Feature Tested | Expected Gateway Action |
|:---|:---|:---|:---|
| `benign_company_handbook.md` | Benign | Standard corporate policies & employee procedures | **APPROVED & INDEXED**: Low heuristic score, verified HMAC signature. |
| `benign_technical_spec.html` | Benign | HTML microservice technical specification | **APPROVED & INDEXED**: Clean HTML parsing, passive expository text. |
| `poisoned_zero_width_bom.txt` | Adversarial | Zero-width unicode smuggling (`\u200B`, `\u200C`, `\uFEFF`) and Cyrillic homoglyphs (`\u0456`, `\u0430`, `\u0435`) | **SANITIZED & FLAGGED**: Invisible bytes stripped, homoglyphs normalized to Latin, and high-risk override caught. |
| `poisoned_hidden_css.html` | Adversarial | Concealed CSS text (`display:none`, `font-size:0px`, `opacity:0`) and comment smuggling | **SANITIZED & STRIPPED**: Hidden elements and comment blocks purged prior to vector embedding. |
| `poisoned_indirect_prompt_injection.md` | Adversarial | High instruction density, imperative jailbreak commands, DAN-style override | **QUARANTINED AT INGESTION**: Fails heuristic risk threshold (0.60) and instruction density limit (0.35). |
| `poisoned_delimiter_escape.txt` | Adversarial | Boundary breakout attempt (`</untrusted_retrieved_context>`) | **NEUTRALIZED & QUARANTINED**: Delimiter tags escaped into `&lt;/untrusted_retrieved_context&gt;` or quarantined. |
