# application/use_cases/add_ioc.py
from application.dto import IOCDTO
from infrastructure.database.repositories import IOCRepository, commit_transaction
from infrastructure.logging.logger import get_logger
from typing import Optional
import re

logger = get_logger('use_cases')

class AddIOCUseCase:
    """Caso de uso para agregar un IOC a un caso existente"""
    
    def __init__(self, ioc_repo: IOCRepository):
        self.ioc_repo = ioc_repo
    
    def _validate_ip(self, ip: str) -> bool:
        """Validar formato de IP"""
        ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        if ipv4_pattern.match(ip):
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validar formato básico de dominio"""
        domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$')
        return bool(domain_pattern.match(domain))
    
    def execute(self, case_id: int, value: str, type: str, 
                direction: str, is_internal: bool = False) -> IOCDTO:
        """
        Agregar un nuevo IOC a un caso
        """
        logger.info(f"Adding IOC {value} to case {case_id}")
        
        try:
            # Validaciones
            if not value:
                raise ValueError("IOC value is required")
            
            if type == 'ip' and not self._validate_ip(value):
                raise ValueError(f"Invalid IP format: {value}")
            elif type == 'domain' and not self._validate_domain(value):
                raise ValueError(f"Invalid domain format: {value}")
            
            # Validar que solo haya una IP source por caso
            if direction == 'source':
                existing = self.ioc_repo.get_by_case(case_id, direction='source')
                if existing:
                    raise ValueError(f"Case {case_id} already has a source IP")
            
            # Crear IOC
            ioc = self.ioc_repo.create(
                case_id=case_id,
                value=value,
                type=type,
                direction=direction,
                is_internal=is_internal
            )
            
            commit_transaction()
            logger.info(f"IOC {value} added successfully")
            
            return IOCDTO.from_model(ioc)
            
        except Exception as e:
            logger.error(f"Error adding IOC: {str(e)}")
            raise
