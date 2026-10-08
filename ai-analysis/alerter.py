import sqlite3
import datetime
from typing import Dict, Any

class Alerter:
    def __init__(self, db_path: str = "threats.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    threat_type TEXT,
                    severity_score INTEGER,
                    explanation TEXT,
                    details TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Alerter Error: Failed to initialize SQLite database: {e}")

    def save_alert(self, threat_type: str, severity_score: int, explanation: str, details: str):
        """
        Saves the alert to the SQLite database.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now_str = datetime.datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO alerts (timestamp, threat_type, severity_score, explanation, details)
                VALUES (?, ?, ?, ?, ?)
            """, (now_str, threat_type, severity_score, explanation, details))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Alerter Error: Failed to save alert to SQLite: {e}")

    def trigger_alert(self, threat_type: str, severity_score: int, explanation: str, details: str):
        """
        Saves the alert to SQLite and displays it in the terminal with appropriate colors.
        """
        # Save to database
        self.save_alert(threat_type, severity_score, explanation, details)
        
        # Color coding configuration based on score
        # 1-3: Low/Info (Cyan)
        # 4-6: Medium (Yellow)
        # 7-10: High/Critical (Red)
        if severity_score >= 7:
            color = "\033[91m"  # Bright Red
            level = "CRÍTICO"
        elif severity_score >= 4:
            color = "\033[93m"  # Bright Yellow
            level = "AVISO"
        else:
            color = "\033[92m"  # Bright Green
            level = "INFORMAÇÃO"
        
        reset = "\033[0m"
        bold = "\033[1m"
        
        print("\n" + "=" * 60)
        print(f"{color}{bold}[!] AMEAÇA DETECTADA - NÍVEL {severity_score} ({level}){reset}")
        print(f"{bold}Timestamp:{reset} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{bold}Classificação:{reset} {threat_type}")
        print(f"{bold}Pontuação de Severidade:{reset} {color}{severity_score}/10{reset}")
        print(f"{bold}Explicação:{reset} {explanation}")
        print(f"{bold}Regras Ativadas / Detalhes do Resumo:{reset}\n{details}")
        print("=" * 60 + "\n")
