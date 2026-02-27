# infrastructure/analyzers/ibm.py
from infrastructure.analyzers.base import BaseAnalyzer, AnalyzerResult
from typing import Dict, Any
import base64

class IBMAnalyzer(BaseAnalyzer):
    """Analyzer para IBM X-Force Exchange API"""
    
    BASE_URL = "https://api.xforce.ibmcloud.com"
    
    def __init__(self, api_key: str, timeout: int = 10):
        # IBM usa API key y password (usamos api_key como "key:password")
        super().__init__(api_key, timeout)
        
    def _get_headers(self) -> Dict[str, str]:
        # IBM requiere Basic Auth
        if ':' in self.api_key:
            # Si viene como "key:password"
            auth_string = base64.b64encode(
                self.api_key.encode()
            ).decode()
        else:
            # Si solo es key, asumimos formato específico
            auth_string = base64.b64encode(
                f"{self.api_key}:".encode()
            ).decode()
            
        return {
            "Authorization": f"Basic {auth_string}",
            "Accept": "application/json"
        }
    
    def analyze(self, value: str) -> AnalyzerResult:
        """
        Analizar IP o dominio en IBM X-Force
        """
        # Determinar si es IP o dominio
        if self._is_ip(value):
            url = f"{self.BASE_URL}/ipr/{value}"
        else:
            url = f"{self.BASE_URL}/resolve/{value}"
        
        response_data = self._make_request(url)
        
        if 'error' in response_data:
            return AnalyzerResult(
                source='ibm',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response=response_data,
                error=response_data['error']
            )
        
        return self._parse_response(response_data)
    
    def _parse_response(self, response: Dict[str, Any]) -> AnalyzerResult:
        """
        Parsear respuesta de IBM X-Force
        IBM usa score 0-10 normalmente
        """
        try:
            # IBM da score 0-10, multiplicamos por 10
            if 'score' in response:
                raw_score = response.get('score', 0) * 10
            elif 'risk_score' in response:
                raw_score = response.get('risk_score', 0) * 10
            else:
                raw_score = 0
            
            # Información adicional
            categories = response.get('cats', {})
            total_reports = len(categories) if categories else 0
            
            # Determinar si es malicioso basado en categorías
            malicious_cats = [cat for cat in categories.keys() 
                            if 'malicious' in cat.lower() or 'attack' in cat.lower()]
            
            normalized = self.normalize_score(raw_score)
            
            return AnalyzerResult(
                source='ibm',
                raw_score=raw_score,
                normalized_score=normalized,
                classification=self.get_classification(normalized),
                raw_response={
                    'score': raw_score,
                    'categories': categories,
                    'total_reports': total_reports,
                    'malicious_categories': len(malicious_cats),
                    'country': response.get('geo', {}).get('country', 'Unknown'),
                    'created': response.get('created', '')
                }
            )
            
        except Exception as e:
            return AnalyzerResult(
                source='ibm',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response={},
                error=f'parse_error: {str(e)}'
            )
    
    def _is_ip(self, value: str) -> bool:
        """Verificar si el valor es una IP"""
        parts = value.split('.')
        return len(parts) == 4 and all(p.isdigit() for p in parts)