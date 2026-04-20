# Retrieval-Augmented Generation (RAG)

## Defense-in-depth approach

By: TryHackMe

<img width="2400" height="1178" alt="image" src="https://github.com/user-attachments/assets/f23bfccd-4552-49d1-a72a-5f870d7933c8" />

### 1) Guardrails on Retrieved Content

Guardrails aim to limit how retrieved content can influences the model.

Common approaches include:

1) Limiting how retrieved text is inserted into prompts

2) Separating retrieved data from system instructions

3) Applying heuristics to flag instruction-like patterns

### 2) Validation During Ingestion

Strong ingestion controls prevent many issues before retrieval occurs.

Effective validation includes:

1) Reviewing document sources

2) Enforcing approval workflows

3) Tracking ownership and update history

### 3) Monitoring and Output Review

Even with guardrails and validation, failures can still occur.

Monitoring should focus on behavioural signals such as:

1) Unusual retrieval patterns

2) Repeated retrieval of the same documents

3) Gradual changes in response tone or behaviour

