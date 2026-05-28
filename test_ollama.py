import requests
import sys
from ollama_client import OllamaClient

def test_ollama_connection():
    print("Testing connection to Ollama API at http://localhost:11434...")
    try:
        # Check /api/tags to see list of models
        res = requests.get("http://localhost:11434/api/tags", timeout=5)
        res.raise_for_status()
        models = res.json().get("models", [])
        model_names = [m["name"] for m in models]
        print(f"Connection successful! Found models: {model_names}")
        
        target_model = "mistral:7b-instruct-q4_K_M"
        # Match base name or exact name (ollama sometimes appends :latest or similar)
        matching_models = [m for m in model_names if target_model in m or m in target_model]
        if not matching_models:
            print(f"Warning: Target model '{target_model}' was not found in available models.")
            print("Will attempt to use it anyway, or you can check 'ollama list' in WSL.")
        else:
            print(f"Target model '{target_model}' is available.")
            
    except Exception as e:
        print(f"Error connecting to Ollama: {e}")
        print("Please ensure Ollama is running inside WSL or on localhost.")
        sys.exit(1)

def test_model_inference():
    client = OllamaClient()
    
    test_event = (
        "Time window: 2026-05-24T19:00:00 to 2026-05-24T19:00:30\n"
        "Suspicious log events:\n"
        "- 12 failed SSH login attempts for user 'root' from IP 192.168.1.150 on port 22 within 15 seconds.\n"
        "Active connections:\n"
        "- 192.168.1.150 connected to local port 22 in ESTABLISHED state."
    )
    
    print("\nSending sample suspicious events to Ollama model...")
    print(f"Sample Event Data:\n{test_event}\n")
    print("Waiting for response (this may take a few seconds on a local GPU)...")
    
    result = client.analyze_event(test_event)
    
    print("\nResponse from Ollama:")
    print("-" * 40)
    print(f"Classification: {result.get('classification')}")
    print(f"Severity Score: {result.get('score')}")
    print(f"Explanation:    {result.get('explanation')}")
    print("-" * 40)

if __name__ == "__main__":
    test_ollama_connection()
    test_model_inference()
