# plugins/server_mode/auth.py
"""
Módulo de autenticación para server mode
Implementa autenticación básica y manejo de usuarios
"""
from functools import wraps
from flask import request, jsonify, g, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
from datetime import datetime, timedelta
import uuid
from app.extensions import db
from infrastructure.logging.logger import get_logger

logger = get_logger('auth')

# Modelo de usuario para server mode
class User(db.Model):
    """Modelo de usuario para autenticación"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(200))
    role = db.Column(db.String(50), default='analyst')  # admin, analyst, viewer
    
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(36))
    
    # Preferencias
    preferences = db.Column(db.JSON, default={})
    
    # Tokens
    api_key = db.Column(db.String(100), unique=True)
    api_key_expires = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        self.api_key = str(uuid.uuid4())
        self.api_key_expires = datetime.utcnow() + timedelta(days=365)
        return self.api_key
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AuthManager:
    """Gestor de autenticación para server mode"""
    
    def __init__(self, app=None):
        self.app = app
        self.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        self.secret_key = app.config.get('SECRET_KEY', self.secret_key)
        
        # Registrar comandos de flask
        self._register_commands()
    
    def _register_commands(self):
        """Registrar comandos CLI para gestión de usuarios"""
        import click
        from flask.cli import with_appcontext
        
        @self.app.cli.command('create-user')
        @click.argument('username')
        @click.argument('email')
        @click.argument('password')
        @click.option('--role', default='analyst', help='User role (admin/analyst/viewer)')
        @with_appcontext
        def create_user_command(username, email, password, role):
            """Crear un nuevo usuario"""
            user = self.create_user(username, email, password, role)
            if user:
                click.echo(f"✅ User {username} created successfully with role {role}")
            else:
                click.echo("❌ Failed to create user")
        
        @self.app.cli.command('list-users')
        @with_appcontext
        def list_users_command():
            """Listar todos los usuarios"""
            users = User.query.all()
            for user in users:
                click.echo(f"{user.username} ({user.email}) - {user.role} - {'Active' if user.is_active else 'Inactive'}")
    
    def create_user(self, username, email, password, role='analyst'):
        """Crear un nuevo usuario"""
        try:
            # Verificar si ya existe
            if User.query.filter_by(username=username).first():
                logger.error(f"Username {username} already exists")
                return None
            
            if User.query.filter_by(email=email).first():
                logger.error(f"Email {email} already exists")
                return None
            
            user = User(
                username=username,
                email=email,
                role=role
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"User {username} created successfully")
            return user
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            db.session.rollback()
            return None
    
    def authenticate(self, username, password):
        """Autenticar usuario por username/password"""
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Generar token JWT
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(hours=8)
            }, self.secret_key, algorithm='HS256')
            
            return {
                'token': token,
                'user': user.to_dict()
            }
        
        return None
    
    def authenticate_api_key(self, api_key):
        """Autenticar por API key"""
        user = User.query.filter_by(
            api_key=api_key,
            is_active=True
        ).filter(
            User.api_key_expires > datetime.utcnow()
        ).first()
        
        if user:
            return user
        
        return None
    
    def verify_token(self, token):
        """Verificar token JWT"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if user and user.is_active:
                return user
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
        
        return None


# Decoradores de autenticación
def login_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user = auth_manager.verify_token(token)
            
            if user:
                g.user = user
                return f(*args, **kwargs)
        
        # Verificar API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = auth_manager.authenticate_api_key(api_key)
            if user:
                g.user = user
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Authentication required'}), 401
    
    return decorated_function


def role_required(required_role):
    """Decorador para requerir rol específico"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = g.get('user')
            
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Roles: admin > analyst > viewer
            role_hierarchy = {
                'admin': 3,
                'analyst': 2,
                'viewer': 1
            }
            
            user_level = role_hierarchy.get(user.role, 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            if user_level >= required_level:
                return f(*args, **kwargs)
            
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        return decorated_function
    return decorator


# Middleware de autenticación para Flask
class AuthMiddleware:
    """Middleware para autenticación en server mode"""
    
    def __init__(self, app):
        self.app = app
        self.auth_manager = AuthManager(app)
        
    def __call__(self, environ, start_response):
        # Aquí se podría implementar lógica de autenticación a nivel WSGI
        return self.app(environ, start_response)


# Instancia global del auth manager
auth_manager = AuthManager()


# Funciones de utilidad para server mode
def init_server_mode(app):
    """Inicializar server mode (autenticación, PostgreSQL, etc.)"""
    logger.info("Initializing SERVER MODE")
    
    # Configurar auth manager
    auth_manager.init_app(app)
    
    # Registrar blueprint de autenticación si es necesario
    from flask import Blueprint
    auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
    
    @auth_bp.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        result = auth_manager.authenticate(username, password)
        
        if result:
            return jsonify(result)
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    @auth_bp.route('/me', methods=['GET'])
    @login_required
    def me():
        return jsonify(g.user.to_dict())
    
    @auth_bp.route('/api-key', methods=['POST'])
    @login_required
    def generate_api_key():
        user = g.user
        api_key = user.generate_api_key()
        db.session.commit()
        return jsonify({'api_key': api_key, 'expires': user.api_key_expires.isoformat()})
    
    app.register_blueprint(auth_bp)
    
    logger.info("Server mode initialized with authentication")
    
    return auth_manager


# Comandos para gestión de base de datos PostgreSQL
def create_postgres_tables(app):
    """Crear tablas PostgreSQL para server mode"""
    with app.app_context():
        # Crear tablas específicas de server mode
        db.create_all()
        
        # Crear vistas materializadas si existen
        try:
            db.session.execute("""
                CREATE MATERIALIZED VIEW IF NOT EXISTS case_summary_mv AS
                SELECT 
                    sc.id,
                    sc.case_number,
                    sc.title,
                    sc.status,
                    sc.severity_global as severity,
                    DATE(sc.created_at) as created_date,
                    COUNT(DISTINCT si.id) as ioc_count,
                    MAX(sia.final_score) as max_score,
                    AVG(sia.final_score) as avg_score,
                    jsonb_agg(DISTINCT sia.classification) as classifications
                FROM server_cases sc
                LEFT JOIN server_iocs si ON si.case_id = sc.id
                LEFT JOIN server_ioc_analysis sia ON sia.ioc_id = si.id
                GROUP BY sc.id;
            """)
            db.session.commit()
            logger.info("Materialized views created")
        except Exception as e:
            logger.warning(f"Could not create materialized view: {e}")
        
        logger.info("PostgreSQL tables created successfully")


# Script de migración completo
MIGRATION_SCRIPT = """
-- Migración completa de SQLite a PostgreSQL

-- 1. Crear tablas en PostgreSQL
-- (Ejecutar primero con create_postgres_tables())

-- 2. Exportar desde SQLite
/*
sqlite3 soc_case.db <<EOF
.mode csv
.headers on
.output cases_export.csv
SELECT * FROM cases;
EOF
*/

-- 3. Importar a PostgreSQL
/*
\\copy server_cases(id, case_number, title, description, corrective_action, conclusion, severity_global, status, created_at, updated_at) 
FROM 'cases_export.csv' DELIMITER ',' CSV HEADER;
*/

-- 4. Actualizar secuencias
SELECT setval('server_cases_id_seq', (SELECT MAX(id)::bigint FROM server_cases));

-- 5. Crear índices adicionales
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_server_cases_status ON server_cases(status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_server_cases_severity ON server_cases(severity_global);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_server_iocs_value ON server_iocs(value);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_server_ioc_analysis_score ON server_ioc_analysis(final_score);
"""
