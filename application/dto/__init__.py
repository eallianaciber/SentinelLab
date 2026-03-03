# application/dto/__init__.py
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime

@dataclass
class CaseDTO:
    """DTO para casos"""
    id: Optional[int]
    case_number: str
    title: str
    description: str
    corrective_action: str
    conclusion: Optional[str]
    severity_global: int
    status: str
    created_at: datetime
    updated_at: Optional[datetime]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Convertir datetime a string
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_model(cls, model):
        """Crear DTO desde modelo SQLAlchemy"""
        return cls(
            id=model.id,
            case_number=model.case_number,
            title=model.title,
            description=model.description or '',
            corrective_action=model.corrective_action or '',
            conclusion=model.conclusion,
            severity_global=model.severity_global,
            status=model.status,
            created_at=model.created_at,
            updated_at=model.updated_at
        )


@dataclass
class AssetDTO:
    """DTO para assets"""
    id: Optional[int]
    case_id: int
    unit: str
    hostname: str
    os: str
    source_ip: str
    mac: str
    user: str
    firewall: str
    antimalware: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_model(cls, model):
        return cls(
            id=model.id,
            case_id=model.case_id,
            unit=model.unit or '',
            hostname=model.hostname,
            os=model.os or '',
            source_ip=model.source_ip,
            mac=model.mac,
            user=model.user,
            firewall=model.firewall or '',
            antimalware=model.antimalware or ''
        )


@dataclass
class ContactDTO:
    """DTO para contactos"""
    id: Optional[int]
    case_id: int
    responsible_name: str
    email: str
    phone_mobile: str
    phone_internal: str
    contact_date: Optional[datetime]
    communication_details: str
    contacted: bool
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.contact_date:
            data['contact_date'] = self.contact_date.isoformat()
        return data
    
    @classmethod
    def from_model(cls, model):
        return cls(
            id=model.id,
            case_id=model.case_id,
            responsible_name=model.responsible_name or '',
            email=model.email or '',
            phone_mobile=model.phone_mobile,
            phone_internal=model.phone_internal or '',
            contact_date=model.contact_date,
            communication_details=model.communication_details or '',
            contacted=model.contacted
        )


@dataclass
class IOCDTO:
    """DTO para IOCs"""
    id: Optional[int]
    case_id: int
    value: str
    type: str
    direction: str
    is_internal: bool
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_model(cls, model):
        return cls(
            id=model.id,
            case_id=model.case_id,
            value=model.value,
            type=model.type,
            direction=model.direction,
            is_internal=model.is_internal,
            created_at=model.created_at
        )


@dataclass
class IOCAnalysisDTO:
    """DTO para análisis de IOC"""
    id: Optional[int]
    ioc_id: int
    vt_score: float
    abuse_score: float
    greynoise_score: float
    ibm_score: float
    consensus_percentage: float
    final_score: float
    classification: str
    analyzed_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.analyzed_at:
            data['analyzed_at'] = self.analyzed_at.isoformat()
        return data
    
    @classmethod
    def from_model(cls, model):
        return cls(
            id=model.id,
            ioc_id=model.ioc_id,
            vt_score=model.vt_score,
            abuse_score=model.abuse_score,
            greynoise_score=model.greynoise_score,
            ibm_score=model.ibm_score,
            consensus_percentage=model.consensus_percentage,
            final_score=model.final_score,
            classification=model.classification or '',
            analyzed_at=model.analyzed_at
        )


@dataclass
class CreateCaseRequest:
    """Request DTO para crear caso"""
    title: str
    description: str
    corrective_action: str
    source_ip: str
    destination_ips: List[str]
    # Asset data
    hostname: str = "---"
    os: str = ""
    mac: str = "---"
    user: str = "---"
    firewall: str = ""
    antimalware: str = ""
    unit: str = ""
    # Contact data (opcional)
    enable_contact: bool = False
    responsible_name: str = ""
    email: str = ""
    phone_mobile: str = "---"
    phone_internal: str = ""
    communication_details: str = ""
    contacted: bool = False
    # Conclusión (opcional)
    conclusion: str = ""


@dataclass
class CreateCaseResponse:
    """Response DTO para creación de caso"""
    case: CaseDTO
    asset: Optional[AssetDTO]
    contact: Optional[ContactDTO]
    iocs: List[IOCDTO]
    analysis_results: Dict[str, Any]


@dataclass
class AnalysisResult:
    """DTO para resultado de análisis"""
    ioc_value: str
    scores: Dict[str, float]
    final_score: float
    classification: str
    sources_contributing: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ioc_value': self.ioc_value,
            'scores': self.scores,
            'final_score': round(self.final_score, 2),
            'classification': self.classification,
            'sources': self.sources_contributing
        }