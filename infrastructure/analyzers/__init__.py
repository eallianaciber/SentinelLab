# infrastructure/analyzers/__init__.py
from infrastructure.analyzers.virustotal import VirusTotalAnalyzer
from infrastructure.analyzers.abuseipdb import AbuseIPDBAnalyzer
from infrastructure.analyzers.greynoise import GreyNoiseAnalyzer
from infrastructure.analyzers.ibm import IBMAnalyzer
from typing import Dict, Optional
from infrastructure.logging.logger import get_logger

logger = get_logger('analyzers')

class AnalyzerFactory:
    """Factory para crear analyzers según configuración"""
    
    @staticmethod
    def create_analyzers(config: Dict) -> Dict[str, Optional[object]]:
        """
        Crear instancias de analyzers basado en configuración
        Retorna dict con analyzers disponibles (los que tienen API key)
        """
        analyzers = {}
        
        # VirusTotal
        if config.get('VIRUSTOTAL_API_KEY'):
            try:
                analyzers['virustotal'] = VirusTotalAnalyzer(
                    config['VIRUSTOTAL_API_KEY']
                )
                logger.info("VirusTotal analyzer initialized")
            except Exception as e:
                logger.error(f"Failed to initialize VirusTotal: {e}")
                analyzers['virustotal'] = None
        else:
            logger.warning("VIRUSTOTAL_API_KEY not set")
            analyzers['virustotal'] = None
        
        # AbuseIPDB
        if config.get('ABUSEIPDB_API_KEY'):
            try:
                analyzers['abuseipdb'] = AbuseIPDBAnalyzer(
                    config['ABUSEIPDB_API_KEY']
                )
                logger.info("AbuseIPDB analyzer initialized")
            except Exception as e:
                logger.error(f"Failed to initialize AbuseIPDB: {e}")
                analyzers['abuseipdb'] = None
        else:
            logger.warning("ABUSEIPDB_API_KEY not set")
            analyzers['abuseipdb'] = None
        
        # GreyNoise
        if config.get('GREYNOISE_API_KEY'):
            try:
                analyzers['greynoise'] = GreyNoiseAnalyzer(
                    config['GREYNOISE_API_KEY']
                )
                logger.info("GreyNoise analyzer initialized")
            except Exception as e:
                logger.error(f"Failed to initialize GreyNoise: {e}")
                analyzers['greynoise'] = None
        else:
            logger.warning("GREYNOISE_API_KEY not set")
            analyzers['greynoise'] = None
        
        # IBM
        if config.get('IBM_XFORCE_API_KEY'):
            try:
                analyzers['ibm'] = IBMAnalyzer(
                    config['IBM_XFORCE_API_KEY']
                )
                logger.info("IBM X-Force analyzer initialized")
            except Exception as e:
                logger.error(f"Failed to initialize IBM: {e}")
                analyzers['ibm'] = None
        else:
            logger.warning("IBM_XFORCE_API_KEY not set")
            analyzers['ibm'] = None
        
        return analyzers
        
