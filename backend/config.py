# config.py
# Configuration for Attack Path Predictor

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True') == 'True'
    
    # Network scanning
    DEFAULT_SCAN_PORTS = '21,22,80,443,445,3306,3389,8080'
    MAX_SCAN_THREADS = 10
    
    # Graph settings
    MAX_ATTACK_PATHS = 10
    MIN_PATH_PROBABILITY = 0.1
    
    # ML settings
    ML_MODEL_PATH = 'models/attack_predictor_ml.pkl'
    ENABLE_ML_PREDICTIONS = True
    
    # Database
    VULNERABILITY_DB_PATH = 'data/vulnerabilities.json'
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}