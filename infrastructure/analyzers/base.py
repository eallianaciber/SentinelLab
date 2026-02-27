# infrastructure/analyzers/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import requests
from infrastructure.logging.logger import get_logger

logger = get_logger('analyzers')

@dataclass
class AnalyzerResult:
    """Resultado estandarizado de un analyzer"""
    source: str
    raw_score: Any
    normalized_score: float
    classification: str
    raw_response: Dict[str, Any]
    error: Optional[str] = None
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'raw_score': self.raw_score,
            'normalized_score': self.normalized_score,
            'classification': self.classification,
            'error': self.error,
            'cached': self.cached
        }


class BaseAnalyzer(ABC):
    """Clase base abstracta para todos los analyzers"""
    
    def __init__(self, api_key: str, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(self._get_headers())
        
    @abstractmethod
    def _get_headers(self) -> Dict[str, str]:
        """Obtener headers específicos para la API"""
        pass
    
    @abstractmethod
    def analyze(self, value: str) -> AnalyzerResult:
        """Analizar un IOC (IP o dominio)"""
        pass
    
    @abstractmethod
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parsear respuesta específica de la API"""
        pass
    
    def _make_request(self, url: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Realizar petición HTTP con manejo de errores"""
        try:
            response = self.session.get(
                url, 
                params=params, 
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to {self.__class__.__name__}")
            return {'error': 'timeout', 'raw_score': None}
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error to {self.__class__.__name__}")
            return {'error': 'connection_error', 'raw_score': None}
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP {response.status_code} from {self.__class__.__name__}")
            if response.status_code == 429:
                return {'error': 'rate_limited', 'raw_score': None}
            elif response.status_code == 401:
                return {'error': 'invalid_api_key', 'raw_score': None}
            return {'error': f'http_{response.status_code}', 'raw_score': None}
            
        except Exception as e:
            logger.error(f"Unexpected error in {self.__class__.__name__}: {str(e)}")
            return {'error': 'unexpected_error', 'raw_score': None}
    
    def normalize_score(self, raw_score: Any) -> float:
        """
        Normalizar puntuación a escala 0-100
        Puede ser sobrescrito por analyzers específicos
        """
        if raw_score is None:
            return 0.0
        
        try:
            score = float(raw_score)
            # Asumimos que viene en escala 0-100
            return max(0, min(100, score))
        except (TypeError, ValueError):
            return 0.0
    
    def get_classification(self, score: float) -> str:
        """Obtener clasificación basada en score normalizado"""
        if score >= 75:
            return 'malicious'
        elif score >= 40:
            return 'suspicious'
        elif score > 0:
            return 'benign'
        else:
            return 'unknown'