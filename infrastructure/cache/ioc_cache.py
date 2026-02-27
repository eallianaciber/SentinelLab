# infrastructure/cache/ioc_cache.py
from infrastructure.database.repositories import IOCCacheRepository
from infrastructure.database.models import IOCCache
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from infrastructure.logging.logger import get_logger
from app.extensions import db
import json

logger = get_logger('cache')

class IOCCacheManager:
    """
    Gestor de caché para resultados de análisis de IOC
    Implementa patrón Singleton para una instancia única
    """
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, ttl: int = 3600):
        """
        Inicializar gestor de caché
        Args:
            ttl: Time to live en segundos (por defecto 1 hora)
        """
        if not hasattr(self, 'initialized'):
            self.ttl = ttl
            self.repository = IOCCacheRepository()
            self.stats = {
                'hits': 0,
                'misses': 0,
                'sets': 0,
                'expired_cleared': 0
            }
            self.initialized = True
            logger.info(f"IOCCacheManager initialized with TTL={ttl}s")
    
    def get(self, value: str, source: str) -> Optional[Dict[str, Any]]:
        """
        Obtener resultado de caché si existe y no ha expirado
        """
        try:
            cache_entry = self.repository.get(value, source)
            
            if cache_entry:
                self.stats['hits'] += 1
                logger.debug(f"Cache HIT for {value} from {source}")
                return {
                    'value': cache_entry.value,
                    'source': cache_entry.source,
                    'raw_score': cache_entry.raw_score,
                    'normalized_score': cache_entry.normalized_score,
                    'classification': cache_entry.classification,
                    'last_checked': cache_entry.last_checked,
                    'expires_at': cache_entry.expires_at,
                    'cached': True
                }
            else:
                self.stats['misses'] += 1
                logger.debug(f"Cache MISS for {value} from {source}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting from cache: {str(e)}")
            return None
    
    def set(self, value: str, source: str, raw_score: float, 
            normalized_score: float, classification: str) -> bool:
        """
        Guardar resultado en caché
        """
        try:
            cache_entry = self.repository.set(
                value=value,
                source=source,
                raw_score=raw_score,
                normalized_score=normalized_score,
                classification=classification,
                ttl=self.ttl
            )
            
            self.stats['sets'] += 1
            logger.debug(f"Cache SET for {value} from {source}")
            
            # Commit explícito
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error setting cache: {str(e)}")
            db.session.rollback()
            return False
    
    def get_or_analyze(self, value: str, source: str, 
                       analyzer_func, *args, **kwargs) -> Dict[str, Any]:
        """
        Patrón: obtener de caché o analizar y guardar
        """
        # Intentar obtener de caché
        cached = self.get(value, source)
        if cached:
            return cached
        
        # No está en caché, analizar
        try:
            result = analyzer_func(value, *args, **kwargs)
            
            # Guardar en caché si el análisis fue exitoso
            if result and not result.get('error'):
                self.set(
                    value=value,
                    source=source,
                    raw_score=result.get('raw_score', 0),
                    normalized_score=result.get('normalized_score', 0),
                    classification=result.get('classification', 'unknown')
                )
                
                # Añadir metadata de caché
                result['cached'] = False
            else:
                result['cached'] = False
            
            return result
            
        except Exception as e:
            logger.error(f"Error in get_or_analyze: {str(e)}")
            return {
                'source': source,
                'error': str(e),
                'cached': False
            }
    
    def clear_expired(self) -> int:
        """
        Limpiar entradas expiradas de la caché
        Returns: Número de entradas eliminadas
        """
        try:
            count = self.repository.clear_expired()
            db.session.commit()
            
            self.stats['expired_cleared'] += count
            logger.info(f"Cleared {count} expired cache entries")
            return count
            
        except Exception as e:
            logger.error(f"Error clearing expired cache: {str(e)}")
            db.session.rollback()
            return 0
    
    def invalidate(self, value: str, source: Optional[str] = None) -> int:
        """
        Invalidar entradas de caché
        Args:
            value: Valor del IOC
            source: Fuente específica (opcional)
        Returns: Número de entradas eliminadas
        """
        try:
            if source:
                # Eliminar entrada específica
                cache_entry = self.repository.get(value, source)
                if cache_entry:
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return 1
                return 0
            else:
                # Eliminar todas las entradas para este valor
                entries = IOCCache.query.filter_by(value=value).all()
                count = len(entries)
                for entry in entries:
                    db.session.delete(entry)
                db.session.commit()
                return count
                
        except Exception as e:
            logger.error(f"Error invalidating cache: {str(e)}")
            db.session.rollback()
            return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Obtener estadísticas de la caché
        """
        try:
            db_stats = self.repository.get_stats()
            
            # Calcular hit ratio
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_ratio = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'memory_stats': {
                    'hits': self.stats['hits'],
                    'misses': self.stats['misses'],
                    'sets': self.stats['sets'],
                    'expired_cleared': self.stats['expired_cleared'],
                    'total_requests': total_requests,
                    'hit_ratio': round(hit_ratio, 2)
                },
                'database_stats': db_stats,
                'ttl_seconds': self.ttl,
                'ttl_hours': self.ttl / 3600
            }
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {str(e)}")
            return {'error': str(e)}
    
    def warm_up(self, values: List[str], sources: List[str], 
                analyzer_func) -> Dict[str, int]:
        """
        Precargar caché con valores comunes
        Args:
            values: Lista de valores a precargar
            sources: Lista de fuentes
            analyzer_func: Función de análisis a usar
        Returns: Estadísticas de precarga
        """
        results = {
            'success': 0,
            'failed': 0,
            'total': len(values) * len(sources)
        }
        
        for value in values:
            for source in sources:
                try:
                    # Verificar si ya está en caché
                    if not self.get(value, source):
                        result = analyzer_func(value, source)
                        if result and not result.get('error'):
                            results['success'] += 1
                        else:
                            results['failed'] += 1
                except Exception as e:
                    logger.error(f"Warm-up failed for {value}:{source} - {str(e)}")
                    results['failed'] += 1
        
        logger.info(f"Cache warm-up completed: {results}")
        return results
    
    def get_ttl(self) -> int:
        """Obtener TTL actual"""
        return self.ttl
    
    def set_ttl(self, ttl: int) -> None:
        """Actualizar TTL"""
        self.ttl = ttl
        logger.info(f"Cache TTL updated to {ttl}s")
    
    def clear_all(self) -> int:
        """Limpiar toda la caché (solo para pruebas)"""
        try:
            count = IOCCache.query.delete()
            db.session.commit()
            logger.warning(f"Cleared all cache ({count} entries)")
            return count
        except Exception as e:
            logger.error(f"Error clearing all cache: {str(e)}")
            db.session.rollback()
            return 0


# Decorador para cachear automáticamente resultados de analyzers
def cached(ttl_override: Optional[int] = None):
    """
    Decorador para cachear automáticamente resultados de funciones de análisis
    """
    def decorator(func):
        def wrapper(self, value: str, *args, **kwargs):
            # Obtener instancia del cache manager
            cache_manager = IOCCacheManager()
            
            # Determinar fuente desde la clase
            source = self.__class__.__name__.lower().replace('analyzer', '')
            
            # Usar TTL override si se proporciona
            if ttl_override:
                original_ttl = cache_manager.ttl
                cache_manager.set_ttl(ttl_override)
            
            try:
                # Usar get_or_analyze
                result = cache_manager.get_or_analyze(
                    value=value,
                    source=source,
                    analyzer_func=func,
                    self=self,
                    value=value,
                    *args,
                    **kwargs
                )
                
                return result
                
            finally:
                # Restaurar TTL original si se modificó
                if ttl_override:
                    cache_manager.set_ttl(original_ttl)
                    
        return wrapper
    return decorator


# Ejemplo de uso (para pruebas)
if __name__ == '__main__':
    # Configurar caché con TTL de 5 minutos para pruebas
    cache = IOCCacheManager(ttl=300)
    
    # Simular función de análisis
    def mock_analyzer(value, source):
        return {
            'raw_score': 85,
            'normalized_score': 85,
            'classification': 'malicious'
        }
    
    # Probar get_or_analyze
    result1 = cache.get_or_analyze('8.8.8.8', 'virustotal', mock_analyzer)
    print(f"Result 1: {result1}")
    
    # Segunda llamada debería venir de caché
    result2 = cache.get_or_analyze('8.8.8.8', 'virustotal', mock_analyzer)
    print(f"Result 2: {result2}")
    
    # Estadísticas
    stats = cache.get_stats()
    print(f"Cache stats: {stats}")