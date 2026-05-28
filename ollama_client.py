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
            "You are a security expert. Analyze the following summary of network/system events "
            "and classify the activity. You MUST respond in JSON format with exactly three fields:\n"
            "1. \"classification\": string, name of the threat detected in Portuguese (or \"Normal\" if benign)\n"
            "2. \"score\": integer between 1 and 10 representing the severity\n"
            "3. \"explanation\": string, brief justification of the assessment written in Portuguese\n\n"
            "Do not include any extra conversational text outside the JSON object. Example response:\n"
            "{\n"
            "  \"classification\": \"Força Bruta SSH\",\n"
            "  \"score\": 8,\n"
            "  \"explanation\": \"Mais de 10 tentativas de login com falha vindas do mesmo IP em uma janela curta de tempo.\"\n"
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
