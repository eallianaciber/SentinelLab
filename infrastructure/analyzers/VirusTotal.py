# infrastructure/analyzers/virustotal.py
from infrastructure.analyzers.base import BaseAnalyzer, AnalyzerResult
from typing import Dict, Any

class VirusTotalAnalyzer(BaseAnalyzer):
    """Analyzer para VirusTotal API"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def analyze(self, value: str) -> AnalyzerResult:
        """
        Analizar IP o dominio en VirusTotal
        """
        # Determinar si es IP o dominio
        if self._is_ip(value):
            url = f"{self.BASE_URL}/ip_addresses/{value}"
        else:
            url = f"{self.BASE_URL}/domains/{value}"
        
        response_data = self._make_request(url)
        
        if 'error' in response_data:
            return AnalyzerResult(
                source='virustotal',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response=response_data,
                error=response_data['error']
            )
        
        return self._parse_response(response_data)
    
    def _parse_response(self, response: Dict[str, Any]) -> AnalyzerResult:
        """
        Parsear respuesta de VirusTotal
        Extraer stats y calcular score
        """
        try:
            data = response.get('data', {})
            attributes = data.get('attributes', {})
            
            # Obtener estadísticas de detección
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            # Calcular score basado en detecciones maliciosas/sospechosas
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            total = sum(last_analysis_stats.values())
            
            if total > 0:
                # Peso: malicious 100%, suspicious 50%
                raw_score = ((malicious * 100) + (suspicious * 50)) / total
            else:
                raw_score = 0
            
            normalized = self.normalize_score(raw_score)
            
            return AnalyzerResult(
                source='virustotal',
                raw_score=raw_score,
                normalized_score=normalized,
                classification=self.get_classification(normalized),
                raw_response={
                    'stats': last_analysis_stats,
                    'reputation': attributes.get('reputation', 0),
                    'total_votes': attributes.get('total_votes', {})
                }
            )
            
        except Exception as e:
            return AnalyzerResult(
                source='virustotal',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response={},
                error=f'parse_error: {str(e)}'
            )
    
    def _is_ip(self, value: str) -> bool:
        """Verificar si el valor es una IP"""
        # Implementación simple
        parts = value.split('.')
        return len(parts) == 4 and all(p.isdigit() for p in parts)
