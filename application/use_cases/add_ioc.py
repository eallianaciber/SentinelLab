# application/use_cases/create_case.py
from application.dto import CreateCaseRequest, CreateCaseResponse, CaseDTO, AssetDTO, ContactDTO, IOCDTO
from infrastructure.database.repositories import CaseRepository, AssetRepository, ContactRepository, IOCRepository, commit_transaction
from infrastructure.database.models import Case, Asset, Contact, IOC
from infrastructure.logging.logger import get_logger
from typing import Optional
import re

logger = get_logger('use_cases')

class CreateCaseUseCase:
    """Caso de uso para crear un nuevo caso"""
    
    def __init__(self, case_repo: CaseRepository, asset_repo: Optional[AssetRepository] = None,
                 contact_repo: Optional[ContactRepository] = None, ioc_repo: Optional[IOCRepository] = None):
        self.case_repo = case_repo
        self.asset_repo = asset_repo or AssetRepository()
        self.contact_repo = contact_repo or ContactRepository()
        self.ioc_repo = ioc_repo or IOCRepository()
    
    def _validate_ip(self, ip: str) -> bool:
        """Validar formato de IP (IPv4 e IPv6 básico)"""
        # IPv4
        ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        if ipv4_pattern.match(ip):
            # Validar que cada octeto esté en rango 0-255
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        
        # IPv6 (validación básica)
        ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$')
        return bool(ipv6_pattern.match(ip))
    
    def _validate_email(self, email: str) -> bool:
        """Validar formato de email"""
        if not email:
            return True
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_pattern.match(email))
    
    def _sanitize_input(self, value: str) -> str:
        """Sanitizar input básico"""
        if value is None:
            return ""
        # Eliminar caracteres peligrosos básicos
        dangerous = ['<', '>', '"', "'", ';', '--', '/*', '*/']
        result = value
        for d in dangerous:
            result = result.replace(d, '')
        return result.strip()
    
    def execute(self, request: CreateCaseRequest) -> CreateCaseResponse:
        """
        Ejecutar creación de caso
        """
        logger.info(f"Creating new case with title: {request.title}")
        
        try:
            # Validaciones
            if not request.title:
                raise ValueError("Title is required")
            
            if not request.source_ip:
                raise ValueError("Source IP is required")
            
            if not self._validate_ip(request.source_ip):
                raise ValueError(f"Invalid source IP format: {request.source_ip}")
            
            if not request.destination_ips:
                raise ValueError("At least one destination IP is required")
            
            for ip in request.destination_ips:
                if not self._validate_ip(ip):
                    raise ValueError(f"Invalid destination IP format: {ip}")
            
            if request.email and not self._validate_email(request.email):
                raise ValueError(f"Invalid email format: {request.email}")
            
            # Sanitizar inputs
            title = self._sanitize_input(request.title)
            description = self._sanitize_input(request.description)
            corrective_action = self._sanitize_input(request.corrective_action)
            
            # 1. Crear caso
            case = self.case_repo.create(
                title=title,
                description=description,
                corrective_action=corrective_action,
                conclusion=request.conclusion if request.conclusion else None
            )
            
            # 2. Crear asset
            asset = self.asset_repo.create(
                case_id=case.id,
                unit=self._sanitize_input(request.unit),
                hostname=self._sanitize_input(request.hostname),
                os=self._sanitize_input(request.os),
                source_ip=request.source_ip,
                mac=self._sanitize_input(request.mac),
                user=self._sanitize_input(request.user),
                firewall=self._sanitize_input(request.firewall),
                antimalware=self._sanitize_input(request.antimalware)
            )
            
            # 3. Crear contacto si está habilitado
            contact = None
            if request.enable_contact:
                contact = self.contact_repo.create(
                    case_id=case.id,
                    responsible_name=self._sanitize_input(request.responsible_name),
                    email=self._sanitize_input(request.email),
                    phone_mobile=self._sanitize_input(request.phone_mobile),
                    phone_internal=self._sanitize_input(request.phone_internal),
                    communication_details=self._sanitize_input(request.communication_details),
                    contacted=request.contacted
                )
            
            # 4. Crear IOC origen
            source_ioc = self.ioc_repo.create(
                case_id=case.id,
                value=request.source_ip,
                type='ip',
                direction='source',
                is_internal=self._is_private_ip(request.source_ip)
            )
            
            # 5. Crear IOCs destino
            destination_iocs = []
            for ip in request.destination_ips:
                ioc = self.ioc_repo.create(
                    case_id=case.id,
                    value=ip,
                    type='ip',
                    direction='destination',
                    is_internal=self._is_private_ip(ip)
                )
                destination_iocs.append(ioc)
            
            # Commit transacción
            commit_transaction()
            
            logger.info(f"Case created successfully with number: {case.case_number}")
            
            # Preparar respuesta
            return CreateCaseResponse(
                case=CaseDTO.from_model(case),
                asset=AssetDTO.from_model(asset) if asset else None,
                contact=ContactDTO.from_model(contact) if contact else None,
                iocs=[IOCDTO.from_model(source_ioc)] + [IOCDTO.from_model(i) for i in destination_iocs],
                analysis_results={}  # Se llenará después con el análisis
            )
            
        except Exception as e:
            logger.error(f"Error creating case: {str(e)}")
            raise
    
    def _is_private_ip(self, ip: str) -> bool:
        """Determinar si una IP es privada"""
        # Rangos de IP privadas IPv4
        private_ranges = [
            ('10.', 8),
            ('172.16.', 12),
            ('172.17.', 12),
            ('172.18.', 12),
            ('172.19.', 12),
            ('172.20.', 12),
            ('172.21.', 12),
            ('172.22.', 12),
            ('172.23.', 12),
            ('172.24.', 12),
            ('172.25.', 12),
            ('172.26.', 12),
            ('172.27.', 12),
            ('172.28.', 12),
            ('172.29.', 12),
            ('172.30.', 12),
            ('172.31.', 12),
            ('192.168.', 16),
            ('127.', 8),  # localhost
        ]
        
        for prefix, _ in private_ranges:
            if ip.startswith(prefix):
                return True
        return False