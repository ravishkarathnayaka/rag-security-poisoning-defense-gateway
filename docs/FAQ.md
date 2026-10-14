# Frequently Asked Questions (FAQ)

### What is the latency overhead of the defense gateway?
The defense gateway adds less than 1.5ms overhead for unicode sanitization and heuristic scanning per document chunk. Cryptographic HMAC verification adds sub-millisecond overhead.

### Can the gateway run without external embedding APIs?
Yes. The built-in `DeterministicLocalEmbedding` provides 384-dimensional feature-hashed embeddings with zero external API dependencies and zero operational cost.

### How does the gateway prevent delimiter breakout attacks?
The `DefensiveFormatter` automatically escapes any occurrences of closing tags (e.g. `</untrusted_retrieved_context>`) inside chunk content into safe XML entities (`&lt;/untrusted_retrieved_context&gt;`), ensuring the LLM parser treats them strictly as data.
