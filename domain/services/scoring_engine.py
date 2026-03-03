# domain/services/scoring_engine.py
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import statistics

@dataclass
class ScoreResult:
    """Resultado del scoring para un IOC"""
    vt_score: float
    abuse_score: float
    greynoise_score: float
    ibm_score: float
    weighted_score: float
    consensus_bonus: float
    penalty: float
    final_score: float
    classification: str
    sources_contributing: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vt_score': round(self.vt_score, 2),
            'abuse_score': round(self.abuse_score, 2),
            'greynoise_score': round(self.greynoise_score, 2),
            'ibm_score': round(self.ibm_score, 2),
            'weighted_score': round(self.weighted_score, 2),
            'consensus_bonus': round(self.consensus_bonus, 2),
            'penalty': round(self.penalty, 2),
            'final_score': round(self.final_score, 2),
            'classification': self.classification,
            'sources_contributing': self.sources_contributing
        }


class ScoringEngine:
    """
    Motor de scoring 2.0
    Escala 0-100 con pesos configurables
    No depende de base de datos ni Flask
    """
    
    # Rangos de clasificación
    CLASSIFICATION_RANGES = [
        (0, 20, 'benign'),
        (21, 50, 'suspicious'),
        (51, 80, 'malicious'),
        (81, 100, 'critical')
    ]
    
    def __init__(self, weights: Dict[str, float]):
        """
        Inicializar motor con pesos configurables
        Ejemplo: {"virustotal": 0.35, "abuseipdb": 0.25, "greynoise": 0.20, "ibm": 0.20}
        """
        self.weights = weights
        self._validate_weights()
    
    def _validate_weights(self) -> None:
        """Validar que los pesos sumen 1.0"""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:  # Tolerancia de 0.01 por errores de redondeo
            raise ValueError(f"Weights must sum to 1.0, got {total}")
    
    def normalize_score(self, raw_score: Any, source: str) -> float:
        """
        Normalizar puntuaciones de diferentes fuentes a escala 0-100
        Cada fuente puede tener su propia lógica de normalización
        """
        if raw_score is None:
            return 0.0
        
        try:
            raw_score = float(raw_score)
        except (TypeError, ValueError):
            return 0.0
        
        # Normalización específica por fuente
        if source == 'virustotal':
            # VirusTotal: 0-100 directamente o 0-1
            if raw_score <= 1:
                return raw_score * 100
            return min(100, max(0, raw_score))
        
        elif source == 'abuseipdb':
            # AbuseIPDB: 0-100 directamente o 0-1
            if raw_score <= 1:
                return raw_score * 100
            return min(100, max(0, raw_score))
        
        elif source == 'greynoise':
            # GreyNoise: clasificación en texto
            # 'malicious' -> 100, 'suspicious' -> 60, 'benign' -> 20, 'unknown' -> 0
            if isinstance(raw_score, str):
                score_map = {
                    'malicious': 100,
                    'suspicious': 60,
                    'benign': 20,
                    'unknown': 0
                }
                return score_map.get(raw_score.lower(), 0)
            return min(100, max(0, raw_score))
        
        elif source == 'ibm':
            # IBM X-Force: 0-10 normalmente
            return min(100, max(0, raw_score * 10))
        
        else:
            # Normalización genérica
            return min(100, max(0, raw_score))
    
    def calculate_weighted_score(self, scores: Dict[str, float]) -> float:
        """
        Calcular puntuación ponderada según pesos configurados
        """
        weighted_sum = 0.0
        for source, score in scores.items():
            if source in self.weights and score is not None:
                weighted_sum += score * self.weights[source]
        
        return weighted_sum
    
    def calculate_consensus_bonus(self, scores: Dict[str, float], threshold: float = 70.0) -> float:
        """
        Calcular bono de consenso:
        (número de fuentes con score >= threshold / total fuentes) * 20
        """
        sources_above_threshold = 0
        total_sources = len([s for s in scores.values() if s is not None])
        
        if total_sources == 0:
            return 0.0
        
        for score in scores.values():
            if score is not None and score >= threshold:
                sources_above_threshold += 1
        
        return (sources_above_threshold / total_sources) * 20
    
    def calculate_penalty(self, scores: Dict[str, float], max_diff_threshold: float = 70.0) -> float:
        """
        Calcular penalización por dispersión:
        Si max - min > threshold -> penalty = 10
        """
        valid_scores = [s for s in scores.values() if s is not None]
        
        if len(valid_scores) < 2:
            return 0.0
        
        score_range = max(valid_scores) - min(valid_scores)
        
        if score_range > max_diff_threshold:
            return 10.0
        
        return 0.0
    
    def classify_score(self, score: float) -> str:
        """
        Clasificar puntuación según rangos predefinidos
        """
        for min_score, max_score, classification in self.CLASSIFICATION_RANGES:
            if min_score <= score <= max_score:
                return classification
        
        return 'unknown'
    
    def calculate(self, raw_scores: Dict[str, Any]) -> ScoreResult:
        """
        Calcular puntuación final para un IOC
        """
        # Normalizar todas las puntuaciones
        normalized_scores = {}
        sources_contributing = []
        
        for source, raw_score in raw_scores.items():
            if raw_score is not None and source in self.weights:
                normalized = self.normalize_score(raw_score, source)
                normalized_scores[source] = normalized
                if normalized > 0:
                    sources_contributing.append(source)
        
        # Calcular componentes
        weighted_score = self.calculate_weighted_score(normalized_scores)
        consensus_bonus = self.calculate_consensus_bonus(normalized_scores)
        penalty = self.calculate_penalty(normalized_scores)
        
        # Calcular puntuación final
        final_score = weighted_score + consensus_bonus - penalty
        
        # Asegurar que está en rango 0-100
        final_score = max(0, min(100, final_score))
        
        # Clasificar
        classification = self.classify_score(final_score)
        
        return ScoreResult(
            vt_score=normalized_scores.get('virustotal', 0.0),
            abuse_score=normalized_scores.get('abuseipdb', 0.0),
            greynoise_score=normalized_scores.get('greynoise', 0.0),
            ibm_score=normalized_scores.get('ibm', 0.0),
            weighted_score=weighted_score,
            consensus_bonus=consensus_bonus,
            penalty=penalty,
            final_score=final_score,
            classification=classification,
            sources_contributing=sources_contributing
        )
    
    def calculate_batch(self, iocs_scores: List[Dict[str, Any]]) -> List[ScoreResult]:
        """
        Calcular puntuaciones para múltiples IOCs
        """
        return [self.calculate(scores) for scores in iocs_scores]
    
    def get_statistics(self, results: List[ScoreResult]) -> Dict[str, Any]:
        """
        Obtener estadísticas de un lote de resultados
        """
        if not results:
            return {}
        
        final_scores = [r.final_score for r in results]
        
        return {
            'count': len(results),
            'mean_score': statistics.mean(final_scores),
            'median_score': statistics.median(final_scores),
            'min_score': min(final_scores),
            'max_score': max(final_scores),
            'std_dev': statistics.stdev(final_scores) if len(final_scores) > 1 else 0,
            'classifications': {
                cls: sum(1 for r in results if r.classification == cls)
                for cls in ['benign', 'suspicious', 'malicious', 'critical', 'unknown']
            }
        }


# Ejemplo de uso (para pruebas)
if __name__ == '__main__':
    # Configuración de ejemplo
    weights = {
        'virustotal': 0.35,
        'abuseipdb': 0.25,
        'greynoise': 0.20,
        'ibm': 0.20
    }
    
    engine = ScoringEngine(weights)
    
    # Ejemplo de puntuaciones
    raw_scores = {
        'virustotal': 85,
        'abuseipdb': 90,
        'greynoise': 'malicious',
        'ibm': 8.5
    }
    
    result = engine.calculate(raw_scores)
    print("Resultado del scoring:")
    print(f"Final Score: {result.final_score:.2f}")
    print(f"Classification: {result.classification}")
    print(f"Sources: {result.sources_contributing}")
    print(result.to_dict())
