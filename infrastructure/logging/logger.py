# infrastructure/logging/logger.py
import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
import json
import traceback

# Configuración global
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Formato de log estructurado
STRUCTURED_FORMAT = '%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(filename)s:%(lineno)d'
SIMPLE_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Colores para consola (opcional)
COLORS = {
    'DEBUG': '\033[36m',     # Cyan
    'INFO': '\033[32m',      # Green
    'WARNING': '\033[33m',   # Yellow
    'ERROR': '\033[31m',     # Red
    'CRITICAL': '\033[35m',  # Magenta
    'RESET': '\033[0m'
}


class ContextAdapter(logging.LoggerAdapter):
    """
    Adaptador de logger que añade contexto adicional
    """
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})
    
    def process(self, msg, kwargs):
        # Añadir contexto de la petición si existe
        if hasattr(self, 'extra') and self.extra:
            kwargs['extra'] = self.extra
        return msg, kwargs


class StructuredLogger:
    """
    Logger estructurado con rotación y múltiples handlers
    """
    
    _instances = {}
    _log_dir = None
    
    @classmethod
    def configure(cls, log_dir: str = 'logs', max_bytes: int = 10485760, backup_count: int = 5):
        """
        Configuración global del logger
        Args:
            log_dir: Directorio para archivos de log
            max_bytes: Tamaño máximo por archivo (default 10MB)
            backup_count: Número de backups a mantener
        """
        cls._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Configuración básica
        cls.max_bytes = max_bytes
        cls.backup_count = backup_count
    
    def __new__(cls, name: str, level: str = 'INFO'):
        if name not in cls._instances:
            instance = super().__new__(cls)
            instance._initialized = False
            cls._instances[name] = instance
        return cls._instances[name]
    
    def __init__(self, name: str, level: str = 'INFO'):
        if self._initialized:
            return
        
        self.name = name
        self.level = level
        self.logger = logging.getLogger(name)
        self.logger.setLevel(LOG_LEVELS.get(level.upper(), logging.INFO))
        self.logger.propagate = False
        
        # Limpiar handlers existentes
        self.logger.handlers.clear()
        
        # Configurar handlers si tenemos directorio configurado
        if StructuredLogger._log_dir:
            self._setup_handlers()
        
        self._initialized = True
    
    def _setup_handlers(self):
        """Configurar handlers para archivos y consola"""
        
        # Formateadores
        detailed_formatter = logging.Formatter(STRUCTURED_FORMAT)
        simple_formatter = logging.Formatter(SIMPLE_FORMAT)
        
        # Handler para archivo general (app.log)
        app_log_path = os.path.join(StructuredLogger._log_dir, 'app.log')
        app_handler = logging.handlers.RotatingFileHandler(
            app_log_path,
            maxBytes=StructuredLogger.max_bytes,
            backupCount=StructuredLogger.backup_count
        )
        app_handler.setLevel(logging.DEBUG)
        app_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(app_handler)
        
        # Handler para archivo de errores (error.log)
        error_log_path = os.path.join(StructuredLogger._log_dir, 'error.log')
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_path,
            maxBytes=StructuredLogger.max_bytes,
            backupCount=StructuredLogger.backup_count
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(error_handler)
        
        # Handler específico para analyzers si el nombre contiene 'analyzer'
        if 'analyzer' in self.name.lower():
            analyzer_log_path = os.path.join(StructuredLogger._log_dir, 'analyzer.log')
            analyzer_handler = logging.handlers.RotatingFileHandler(
                analyzer_log_path,
                maxBytes=StructuredLogger.max_bytes,
                backupCount=StructuredLogger.backup_count
            )
            analyzer_handler.setLevel(logging.DEBUG)
            analyzer_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(analyzer_handler)
        
        # Handler para consola (solo en desarrollo)
        if os.getenv('FLASK_ENV') == 'development':
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(simple_formatter)
            self.logger.addHandler(console_handler)
    
    def debug(self, msg: str, extra: Optional[Dict] = None):
        self._log(logging.DEBUG, msg, extra)
    
    def info(self, msg: str, extra: Optional[Dict] = None):
        self._log(logging.INFO, msg, extra)
    
    def warning(self, msg: str, extra: Optional[Dict] = None):
        self._log(logging.WARNING, msg, extra)
    
    def error(self, msg: str, extra: Optional[Dict] = None, exc_info: bool = False):
        if exc_info:
            msg = f"{msg}\n{traceback.format_exc()}"
        self._log(logging.ERROR, msg, extra)
    
    def critical(self, msg: str, extra: Optional[Dict] = None):
        self._log(logging.CRITICAL, msg, extra)
    
    def exception(self, msg: str, extra: Optional[Dict] = None):
        self.error(msg, extra, exc_info=True)
    
    def _log(self, level: int, msg: str, extra: Optional[Dict] = None):
        """Método interno para logging"""
        if extra:
            # Crear adaptador con extra data
            adapter = ContextAdapter(self.logger, extra)
            adapter.log(level, msg)
        else:
            self.logger.log(level, msg)
    
    def get_log_file_paths(self) -> Dict[str, str]:
        """Obtener rutas de los archivos de log"""
        if not StructuredLogger._log_dir:
            return {}
        
        return {
            'app_log': os.path.join(StructuredLogger._log_dir, 'app.log'),
            'error_log': os.path.join(StructuredLogger._log_dir, 'error.log'),
            'analyzer_log': os.path.join(StructuredLogger._log_dir, 'analyzer.log') if 'analyzer' in self.name.lower() else None
        }


# Factory function para obtener logger
def get_logger(name: str, level: str = 'INFO') -> StructuredLogger:
    """
    Obtener instancia de logger configurada
    """
    return StructuredLogger(name, level)


# Decorador para logging de funciones
def log_function_call(logger_name: str = None):
    """
    Decorador para loggear llamadas a funciones
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger(logger_name or func.__module__)
            
            # Registrar entrada
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            
            try:
                result = func(*args, **kwargs)
                
                # Registrar salida
                logger.debug(f"{func.__name__} returned: {result}")
                return result
                
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
                raise
        
        return wrapper
    return decorator


# Clase para métricas de logging
class LogMetrics:
    """
    Recolector de métricas de logging
    """
    
    def __init__(self):
        self.counts = {
            'DEBUG': 0,
            'INFO': 0,
            'WARNING': 0,
            'ERROR': 0,
            'CRITICAL': 0
        }
        self.start_time = datetime.utcnow()
    
    def increment(self, level: str):
        """Incrementar contador para un nivel"""
        if level in self.counts:
            self.counts[level] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas"""
        total = sum(self.counts.values())
        runtime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            'total_logs': total,
            'logs_per_second': round(total / runtime, 2) if runtime > 0 else 0,
            'runtime_seconds': round(runtime, 2),
            'counts': self.counts,
            'levels_distribution': {
                level: round(count / total * 100, 2) if total > 0 else 0
                for level, count in self.counts.items()
            }
        }


# Inicialización global de logging
def init_logging(app=None):
    """
    Inicializar sistema de logging
    Debe llamarse al inicio de la aplicación
    """
    # Determinar directorio de logs
    if app:
        log_dir = app.config.get('LOG_FOLDER', 'logs')
        max_bytes = app.config.get('LOG_MAX_BYTES', 10485760)
        backup_count = app.config.get('LOG_BACKUP_COUNT', 5)
    else:
        log_dir = 'logs'
        max_bytes = 10485760
        backup_count = 5
    
    # Configurar logging global
    StructuredLogger.configure(log_dir, max_bytes, backup_count)
    
    # Crear loggers principales
    app_logger = get_logger('app')
    db_logger = get_logger('database')
    analyzer_logger = get_logger('analyzers')
    routes_logger = get_logger('routes')
    
    app_logger.info("=" * 50)
    app_logger.info("Logging system initialized")
    app_logger.info(f"Log directory: {os.path.abspath(log_dir)}")
    app_logger.info(f"Environment: {os.getenv('FLASK_ENV', 'production')}")
    app_logger.info("=" * 50)
    
    return {
        'app': app_logger,
        'database': db_logger,
        'analyzers': analyzer_logger,
        'routes': routes_logger
    }


# Middleware para logging de requests (opcional para Flask)
class RequestLogger:
    """
    Middleware para loggear requests HTTP
    """
    
    def __init__(self, app=None):
        self.app = app
        self.logger = get_logger('http')
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        @app.before_request
        def log_request():
            from flask import request
            self.logger.info(
                f"Request: {request.method} {request.path}",
                extra={
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.user_agent.string if request.user_agent else None
                }
            )
        
        @app.after_request
        def log_response(response):
            from flask import request
            self.logger.info(
                f"Response: {request.method} {request.path} - {response.status_code}",
                extra={
                    'status_code': response.status_code,
                    'content_length': response.content_length
                }
            )
            return response


# Ejemplo de uso (para pruebas)
if __name__ == '__main__':
    # Inicializar logging
    init_logging()
    
    # Obtener loggers
    logger = get_logger('test')
    analyzer_logger = get_logger('analyzers.test')
    
    # Probar diferentes niveles
    logger.debug("Mensaje de debug")
    logger.info("Mensaje informativo")
    logger.warning("Mensaje de advertencia")
    
    try:
        x = 1 / 0
    except Exception:
        logger.error("Error dividiendo por cero", exc_info=True)
    
    # Log con contexto adicional
    logger.info("Usuario autenticado", extra={'user_id': 123, 'action': 'login'})
    
    # Probar logger de analyzer
    analyzer_logger.info("Analizando IP 8.8.8.8")
    
    # Mostrar rutas de logs
    paths = logger.get_log_file_paths()
    print(f"Log files: {paths}")