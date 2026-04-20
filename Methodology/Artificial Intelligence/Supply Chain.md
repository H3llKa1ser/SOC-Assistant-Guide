# AI Supply Chain

## Safe Serialisation Formats

### 1) SafeTensors

Differences between SafeTensors and Pickle formats:

| Feature        | Pickle                                                      | SafeTensors                                              |
|----------------|-------------------------------------------------------------|----------------------------------------------------------|
| **Structure**  | Arbitrary Python bytecode                                   | JSON header + raw binary tensor data                     |
| **Code execution** | Yes – via `__reduce__` and other opcodes                  | No – format cannot encode executable instructions        |
| **Content**    | Any Python object                                           | Only tensor data (weights, biases)                       |
| **Validation** | None – loads and executes blindly                           | Header is parsed and validated before any data is read   |
| **Speed**      | Moderate                                                    | Fast – zero-copy memory mapping                          |

#### Convertion from Pickle to SafeTensors

    import torch
    from safetensors.torch import save_file, load_file
    
    # Step 1: Load the existing pickle model safely
    # (weights_only=True restricts what pickle can do; explained in Defence 2 below)
    model_weights = torch.load("model.pkl", weights_only=True)
    
    # Step 2: Save as SafeTensors
    save_file(model_weights, "model.safetensors")
    
    # Step 3: Load the SafeTensors model (always safe)
    safe_weights = load_file("model.safetensors")

### 2) PyTorch weights_only=True

When you call torch.load(), PyTorch uses pickle internally to deserialise the file. By default, this means pickle's full capability is active, including code execution. Setting weights_only=True tells PyTorch to restrict the unpickler so that it can only reconstruct tensor objects (the numerical weights and biases that make up the model). Any pickle instructions that try to import modules like os or call functions like system() are blocked and raise an error instead of executing.

#### Code difference

    import torch
    
    # UNSAFE: pickle can execute any embedded code
    model = torch.load("model.pt")
    
    # SAFE: pickle is restricted to tensor reconstruction only
    model = torch.load("model.pt", weights_only=True)

## Verification

### 1) SHA-256 Checksum Verification

Check expected checksums (example)

    cat /opt/supply-chain/models/checksums.json

Compute the actual hash of each model and compare it against the expected value

    sha256sum /opt/supply-chain/models/product_recommender.safetensors /opt/supply-chain/models/model_review_v2.pkl /opt/supply-chain/models/product_recommender.pkl

For stronger assurance, look for cryptographic signatures (digital signatures) on model artefacts.

### 2) Model Cards

A model card is documentation that ships with a model, describing what it does, how it was trained, and where it falls short. The format was proposed by Mitchell et al. (2019) and has since become an industry standard for repositories such as Hugging Face.

When evaluating a model's provenance, check these model card sections:

1) Model details: Author, organisation, version, and licence. No author or missing licence is an immediate red flag.

2) Intended use: What the model is designed for. Vague or overly broad claims suggest a generic or poorly documented model.

3) Training data: Dataset name, size, and source. No training data description is a strong warning sign.

4) Performance: Metrics on standard benchmarks. No metrics, or unrealistically high claims, warrant scepticism.

5) Limitations: Known failure modes and biases. Every model has limitations. A card with none is incomplete.

A missing or sparse model card is one of the strongest warning signs of a suspicious model. Legitimate model authors invest significant effort in documentation.

### 3) Model Acquisition Framework

| Step               | Action                                                                                                                        | Purpose                                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **1. Quarantine**  | Download the model into an isolated staging area — never directly into production                                             | Prevent untested artefacts from reaching live systems                                                       |
| **2. Source verification** | Verify the author, organisation, and repository. Check for verification badges, publication history, and community reputation | Establish provenance and credibility                                                                        |
| **3. Integrity check** | Compute SHA-256 checksums and compare against the author's published values                                                | Confirm the file has not been tampered with in transit                                                       |
| **4. Security scan** | Run Fickling, ModelScan, and dependency auditing tools. Inspect the model card for completeness                              | Detect malicious content and known vulnerabilities                                                           |
| **5. Approve or reject** | Based on findings, either promote the model to production or quarantine permanently                                      | Enforce a gate between untested and trusted artefacts                                                        |

The framework above assumes you have a file. When you consume a model through an API, the gates look different: there is no checksum to verify, no model file to scan. But the governance instinct remains the same: you are still deciding whether to trust an artefact you did not build.

## Model Scanning

### 1) Fickling: Static Pickle Analysis

Run the tool on different models to compare

    fickling /opt/supply-chain/models/model_review_v2.pkl

Run an automated safety check

    fickling --check-safety -p /opt/supply-chain/models/model_review_v2.pkl

### 2) ModelScan: Multi-Format Model Scanning

Run scan on a model

    modelscan -p /opt/supply-chain/models/model_review_v2.pkl

#### Scanner results interpretation

| Severity   | Meaning                                                          | Action                                                   |
|------------|------------------------------------------------------------------|----------------------------------------------------------|
| **CRITICAL** | Confirmed dangerous operation (e.g., `os.system`, `subprocess`) | Do not use — quarantine immediately                      |
| **HIGH**     | Likely dangerous operation (e.g., `eval`, network calls)        | Do not use without thorough review                       |
| **MEDIUM**   | Suspicious but potentially legitimate (e.g., custom unpickler)  | Review carefully before use                              |
| **LOW**      | Informational (e.g., non-standard pickle opcodes)               | Note and monitor                                         |

## Behavioral Analysis

Example model load that generates a session event stream:

    SESSION START — model_load
    MODEL LOAD BEGIN — /models/sentiment_model.pkl (pickle)
    FILE ACCESS — /models/sentiment_model.pkl (rb) [normal]
    MODEL LOAD COMPLETE — object_type: SentimentModel
    SESSION STOP — model_load

Monitor for any suspicious signs in the telemetry.
