# app/factory.py
from flask import Flask
from app.config import config
from app.extensions import db
import os

def create_app(config_name=None):
    """Application factory"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    
    # Register routes blueprint
    from app.routes.case_routes import case_bp
    app.register_blueprint(case_bp, url_prefix='/api/cases')
    
    # Create exports folder if it doesn't exist
    exports_path = os.path.join(app.root_path, '..', app.config['EXPORTS_FOLDER'])
    os.makedirs(exports_path, exist_ok=True)
    
    # Create logs folder
    logs_path = os.path.join(app.root_path, '..', app.config['LOG_FOLDER'])
    os.makedirs(logs_path, exist_ok=True)
    
    return app