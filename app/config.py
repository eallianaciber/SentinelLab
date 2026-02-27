# app/config.py
import os
from dotenv import load_dotenv
import json

load_dotenv()

class Config:
    """Configuración base"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    APP_MODE = os.getenv('APP_MODE', 'local')
    
    # Database
    if APP_MODE == 'local':
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///soc_case.db')
    else:
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY', '')
    IBM_XFORCE_API_KEY = os.getenv('IBM_XFORCE_API_KEY', '')
    
    # Cache
    IOC_CACHE_TTL = int(os.getenv('IOC_CACHE_TTL', 3600))
    
    # Scoring
    SCORING_WEIGHTS_JSON = os.getenv('SCORING_WEIGHTS', 
        '{"virustotal":0.35,"abuseipdb":0.25,"greynoise":0.20,"ibm":0.20}')
    
    @property
    def SCORING_WEIGHTS(self):
        return json.loads(self.SCORING_WEIGHTS_JSON)
    
    # Paths
    EXPORTS_FOLDER = 'exports'
    
    # Logging
    LOG_FOLDER = 'logs'
    LOG_MAX_BYTES = 10485760  # 10MB
    LOG_BACKUP_COUNT = 5


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}