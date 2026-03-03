# infrastructure/analyzers/abuseipdb.py
from infrastructure.analyzers.base import BaseAnalyzer, AnalyzerResult
from typing import Dict, Any

class AbuseIPDBAnalyzer(BaseAnalyzer):
    """Analyzer para AbuseIPDB API"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def _get_headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    def analyze(self, value: str) -> AnalyzerResult:
        """
        Analizar IP en AbuseIPDB
        """
        params = {
            'ipAddress': value,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response_data = self._make_request(
            f"{self.BASE_URL}/check",
            params=params
        )
        
        if 'error' in response_data:
            return AnalyzerResult(
                source='abuseipdb',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response=response_data,
                error=response_data['error']
            )
        
        return self._parse_response(response_data)
    
    def _parse_response(self, response: Dict[str, Any]) -> AnalyzerResult:
        """
        Parsear respuesta de AbuseIPDB
        AbuseIPDB ya devuelve confidence score 0-100
        """
        try:
            data = response.get('data', {})
            
            # AbuseIPDB ya da un confidence score 0-100
            raw_score = data.get('abuseConfidenceScore', 0)
            
            # Información adicional
            total_reports = data.get('totalReports', 0)
            country = data.get('countryCode', 'Unknown')
            is_public = data.get('isPublic', True)
            
            normalized = self.normalize_score(raw_score)
            
            return AnalyzerResult(
                source='abuseipdb',
                raw_score=raw_score,
                normalized_score=normalized,
                classification=self.get_classification(normalized),
                raw_response={
                    'abuseConfidenceScore': raw_score,
                    'totalReports': total_reports,
                    'countryCode': country,
                    'isPublic': is_public,
                    'lastReportedAt': data.get('lastReportedAt'),
                    'reports': data.get('reports', [])[:5]  # Solo últimos 5 reportes
                }
            )
            
        except Exception as e:
            return AnalyzerResult(
                source='abuseipdb',
                raw_score=0,
                normalized_score=0,
                classification='unknown',
                raw_response={},
                error=f'parse_error: {str(e)}'
            )
