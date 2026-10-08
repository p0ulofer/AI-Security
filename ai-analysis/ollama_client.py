import json
import requests
from typing import Dict, Any

class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral:7b-instruct-q4_K_M"):
        self.base_url = base_url
        self.model = model
        self.generate_url = f"{base_url}/api/generate"

    def analyze_event(self, event_summary: str) -> Dict[str, Any]:
        """
        Sends the event summary to the local Ollama model for threat analysis.
        Returns a dictionary containing:
        - classification (str): The threat type (e.g. Brute Force, Port Scan, Benign, etc.)
        - score (int): Severity score from 1 (low) to 10 (critical)
        - explanation (str): Brief justification for the classification and score
        """
        system_prompt = (
    "You are an expert network security analyst. You will receive a summary of network events "
    "captured by an IDS (Intrusion Detection System) in a 30-second window.\n\n"
    "The summary contains:\n"
    "- Heuristic rules that were triggered (these are the most important signals)\n"
    "- Raw packet counts and protocol breakdown\n"
    "- Active connections observed\n\n"
    "PRIORITY RULES FOR CLASSIFICATION:\n"
    "- If you see 'SYN flood' + 'Varredura de portas' + 'porta sensível 22' together -> Brute Force SSH or Port Scan, score 9-10\n"
    "- If you see many failed logins from same IP -> Brute Force, score 8-10\n"
    "- If you see port scan across 10+ ports -> Reconnaissance, score 7-9\n"
    "- If you see high volume (>5MB) from unknown IP -> Data Exfiltration or DDoS, score 7-9\n"
    "- If the only signal is conn spike from a known CDN IP (Cloudflare: 172.66.x.x, 104.20.x.x) -> likely benign, score 2-3\n"
    "- If heuristics fired but evidence is weak or from CDN IPs only -> score 1-4\n"
    "- If port 22 is the target and same IP shows repeated connections or conn spike -> classify as Força Bruta SSH, score 8-9, NOT Reconhecimento\n"
    "- Reconhecimento applies only when many DIFFERENT ports are scanned (10+), not repeated connections to the same port\n\n"
    "IMPORTANT: Base your score on the HEURISTIC RULES ACTIVATED section, not just the connection list. "
    "A connection to port 22 from the same IP that triggered SYN flood is strong evidence of brute force.\n\n"
    "You MUST respond in JSON format with exactly three fields:\n"
    "1. \"classification\": string, name of the threat in Portuguese (or \"Normal\" if benign)\n"
    "2. \"score\": integer between 1 and 10 representing severity\n"
    "3. \"explanation\": string, brief justification in Portuguese, mentioning the specific heuristics that led to the score\n\n"
    "Do not include any extra text outside the JSON object. Example:\n"
    "{\n"
    "  \"classification\": \"Força Bruta SSH\",\n"
    "  \"score\": 9,\n"
    "  \"explanation\": \"SYN flood com 2000 pacotes e varredura de 25 portas do IP 172.29.105.246 direcionados à porta 22 indicam ataque de força bruta SSH ativo.\"\n"
    "}"
)

        payload = {
            "model": self.model,
            "prompt": event_summary,
            "system": system_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0
            }
        }

        try:
            response = requests.post(self.generate_url, json=payload, timeout=60)
            response.raise_for_status()
            
            # The Ollama /api/generate returns a JSON response where "response" contains the generated text.
            result_json = response.json()
            model_response_text = result_json.get("response", "").strip()
            
            # Parse the model's text response as JSON since we requested format: "json"
            analysis = json.loads(model_response_text)
            
            # Ensure the required fields exist and are of correct type
            return {
                "classification": str(analysis.get("classification", "Unknown")),
                "score": int(analysis.get("score", 1)),
                "explanation": str(analysis.get("explanation", "Could not parse model explanation."))
            }
        except requests.exceptions.RequestException as e:
            return {
                "classification": "Error",
                "score": 0,
                "explanation": f"HTTP request failed: {str(e)}"
            }
        except json.JSONDecodeError as e:
            return {
                "classification": "Parsing Error",
                "score": 0,
                "explanation": f"Failed to parse LLM response as JSON: {model_response_text[:200]}"
            }
        except Exception as e:
            return {
                "classification": "Error",
                "score": 0,
                "explanation": f"Unexpected error: {str(e)}"
            }
