"""
Configuration for Evil Twin Detector
"""

import os


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'evil_twin_detector.db')
    SCAN_TIMEOUT = 15  # seconds
    MAX_SCAN_HISTORY = 100
    DEBUG = False


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
