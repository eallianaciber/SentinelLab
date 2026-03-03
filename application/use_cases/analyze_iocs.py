# application/use_cases/analyze_iocs.py
from application.dto import AnalysisResult
from infrastructure.database.repositories import IOCRepository, IOCAnalysisRepository, commit_transaction
from infrastructure.cache.ioc_cache import IOCCacheManager
from infrastructure.analyzers import AnalyzerFactory
from domain.services.scoring_engine import ScoringEngine
from infrastructure.logging.logger import get_logger
from typing import List, Dict, Any
from flask import current_app
from typing import Optional, List, Dict

logger = get_logger('use_cases')

class AnalyzeIOCsUseCase:
    """Caso de uso para analizar IOCs de un caso"""
    
    def __init__(self, ioc_repo: IOCRepository, analysis_repo: Optional[IOCAnalysisRepository] = None):
        self.ioc_repo = ioc_repo
        self.analysis_repo = analysis_repo or IOCAnalysisRepository()
        self.cache_manager = IOCCacheManager()
        
        # Inicializar analyzers y scoring engine cuando se ejecute
        self.analyzers = None
        self.scoring_engine = None
    
    def _initialize(self):
        """Inicializar analyzers y scoring engine con configuración actual"""
        if self.analyzers is None and current_app:
            # Obtener configuración de la app
            config = current_app.config
            
            # Crear analyzers
            self.analyzers = AnalyzerFactory.create_analyzers({
                'VIRUSTOTAL_API_KEY': config.get('VIRUSTOTAL_API_KEY'),
                'ABUSEIPDB_API_KEY': config.get('ABUSEIPDB_API_KEY'),
                'GREYNOISE_API_KEY': config.get('GREYNOISE_API_KEY'),
                'IBM_XFORCE_API_KEY': config.get('IBM_XFORCE_API_KEY')
            })
            
            # Crear scoring engine con pesos configurados
            self.scoring_engine = ScoringEngine(config.get('SCORING_WEIGHTS', {}))
    
    def _analyze_with_source(self, ioc_value: str, source: str, analyzer) -> Dict[str, Any]:
        """
        Analizar IOC con una fuente específica, usando caché
        """
        if not analyzer:
            return {'error': 'analyzer_not_available', 'source': source}
        
        try:
            # Usar caché
            result = self.cache_manager.get_or_analyze(
                value=ioc_value,
                source=source,
                analyzer_func=analyzer.analyze
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing {ioc_value} with {source}: {str(e)}")
            return {'error': str(e), 'source': source}
    
    def execute(self, case_id: int) -> List[AnalysisResult]:
        """
        Analizar todos los IOCs de destino de un caso
        """
        logger.info(f"Analyzing IOCs for case {case_id}")
        
        self._initialize()
        
        # Obtener IOCs destino
        iocs = self.ioc_repo.get_destination_iocs(case_id)
        
        if not iocs:
            raise ValueError(f"No destination IOCs found for case {case_id}")
        
        results = []
        
        for ioc in iocs:
            logger.info(f"Analyzing IOC: {ioc.value}")
            
            # Recolectar resultados de todas las fuentes
            raw_scores = {}
            
            # VirusTotal
            if self.analyzers and self.analyzers.get('virustotal'):
                vt_result = self._analyze_with_source(
                    ioc.value, 'virustotal', self.analyzers['virustotal']
                )
                if not vt_result.get('error'):
                    raw_scores['virustotal'] = vt_result.get('normalized_score', 0)
            
            # AbuseIPDB
            if self.analyzers and self.analyzers.get('abuseipdb'):
                abuse_result = self._analyze_with_source(
                    ioc.value, 'abuseipdb', self.analyzers['abuseipdb']
                )
                if not abuse_result.get('error'):
                    raw_scores['abuseipdb'] = abuse_result.get('normalized_score', 0)
            
            # GreyNoise
            if self.analyzers and self.analyzers.get('greynoise'):
                gn_result = self._analyze_with_source(
                    ioc.value, 'greynoise', self.analyzers['greynoise']
                )
                if not gn_result.get('error'):
                    raw_scores['greynoise'] = gn_result.get('normalized_score', 0)
            
            # IBM
            if self.analyzers and self.analyzers.get('ibm'):
                ibm_result = self._analyze_with_source(
                    ioc.value, 'ibm', self.analyzers['ibm']
                )
                if not ibm_result.get('error'):
                    raw_scores['ibm'] = ibm_result.get('normalized_score', 0)
            
            # Calcular score usando scoring engine
            if self.scoring_engine and raw_scores:
                score_result = self.scoring_engine.calculate(raw_scores)
                
                # Guardar análisis en base de datos
                self.analysis_repo.create(
                    ioc_id=ioc.id,
                    analysis_data={
                        'vt_score': score_result.vt_score,
                        'abuse_score': score_result.abuse_score,
                        'greynoise_score': score_result.greynoise_score,
                        'ibm_score': score_result.ibm_score,
                        'consensus_percentage': score_result.consensus_bonus * 5,  # Convertir a porcentaje
                        'final_score': score_result.final_score,
                        'classification': score_result.classification
                    }
                )
                
                # Crear resultado
                result = AnalysisResult(
                    ioc_value=ioc.value,
                    scores={
                        'virustotal': score_result.vt_score,
                        'abuseipdb': score_result.abuse_score,
                        'greynoise': score_result.greynoise_score,
                        'ibm': score_result.ibm_score
                    },
                    final_score=score_result.final_score,
                    classification=score_result.classification,
                    sources_contributing=score_result.sources_contributing
                )
                
                results.append(result)
                
                logger.info(f"IOC {ioc.value} analysis complete - Score: {score_result.final_score}, Classification: {score_result.classification}")
            else:
                logger.warning(f"No scores available for {ioc.value}")
        
        # Commit transacción
        commit_transaction()
        
        return results
