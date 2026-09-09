"""
Configuration settings for the vulnerability assessment framework
"""
import os
from pathlib import Path

class Config:
    """Main configuration class"""
    
    # Project paths
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = BASE_DIR / 'data'
    PAYLOAD_DIR = DATA_DIR / 'payloads'
    OUTPUT_DIR = BASE_DIR / 'output'
    REPORT_DIR = OUTPUT_DIR / 'reports'
    
    # Scanner settings
    USER_AGENT = "PakUniSecurityScanner/1.0 (Educational Purpose Only)"
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    RATE_LIMIT_THRESHOLD = 5
    SCAN_DELAY = 1
    
    # API endpoints
    HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    HIBP_API_KEY = ""
    
    # Enterprise settings
    LICENSE_FILE = "license.key"
    ENTERPRISE_MODE = False
    
    @classmethod
    def init_directories(cls):
        """Create all necessary directories"""
        for dir_path in [cls.DATA_DIR, cls.PAYLOAD_DIR, cls.OUTPUT_DIR, cls.REPORT_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

# Initialize directories on import
Config.init_directories()
print("Configuration loaded successfully!")