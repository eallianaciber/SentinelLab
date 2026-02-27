# infrastructure/analyzers/greynoise.py
from infrastructure.analyzers.base import BaseAnalyzer, AnalyzerResult
from typing import Dict, Any

class GreyNoiseAnalyzer(BaseAnalyzer):
    """Analyzer para GreyNoise API"""
    
    BASE_URL = "https://api.greynoise.io/v3"
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "key": self.api_key,
            "Accept": "application/json"
        }
    
    def analyze(self, value: str) -> AnalyzerResult:
        """
        Analizar IP en GreyNoise
        """
        response_data = self._make_request(
            f"{self.BASE_URL}/community/{value}"
        )
        
        if 'error' in response_data:
            return AnalyzerResult(
                source='greynoise',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response=response_data,
                error=response_data['error']
            )
        
        return self._parse_response(response_data)
    
    def _parse_response(self, response: Dict[str, Any]) -> AnalyzerResult:
        """
        Parsear respuesta de GreyNoise
        GreyNoise clasifica como: malicious, benign, unknown
        """
        try:
            # Mapeo de clasificación a score
            classification_map = {
                'malicious': 100,
                'benign': 20,
                'unknown': 0
            }
            
            classification = response.get('classification', 'unknown').lower()
            raw_score = classification_map.get(classification, 0)
            
            # GreyNoise también da noise y riot status
            noise = response.get('noise', False)
            riot = response.get('riot', False)
            
            normalized = self.normalize_score(raw_score)
            
            return AnalyzerResult(
                source='greynoise',
                raw_score=classification,
                normalized_score=normalized,
                classification=self.get_classification(normalized),
                raw_response={
                    'classification': classification,
                    'noise': noise,
                    'riot': riot,
                    'name': response.get('name', ''),
                    'last_seen': response.get('last_seen', ''),
                    'link': response.get('link', '')
                }
            )
            
        except Exception as e:
            return AnalyzerResult(
                source='greynoise',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response={},
                error=f'parse_error: {str(e)}'
            )