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

