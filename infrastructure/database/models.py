# infrastructure/database/models.py
from app.extensions import db
from sqlalchemy import Index, UniqueConstraint
from datetime import datetime
import re

class Case(db.Model):
    """Modelo de casos de investigación"""
    __tablename__ = 'cases'
    
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    corrective_action = db.Column(db.Text)
    conclusion = db.Column(db.Text)
    severity_global = db.Column(db.Integer, default=0)  # 0-100
    status = db.Column(db.String(20), default='open')  # open/closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    asset = db.relationship('Asset', backref='case', uselist=False, cascade='all, delete-orphan')
    contacts = db.relationship('Contact', backref='case', uselist=False, cascade='all, delete-orphan')
    iocs = db.relationship('IOC', backref='case', cascade='all, delete-orphan')
    
    def generate_case_number(self):
        """Genera un número de caso único"""
        date_str = datetime.utcnow().strftime('%Y%m%d')
        # Buscar el último caso del día para generar secuencia
        last_case = Case.query.filter(
            Case.case_number.like(f"CASE-{date_str}-%")
        ).order_by(Case.case_number.desc()).first()
        
        if last_case:
            last_seq = int(last_case.case_number.split('-')[-1])
            new_seq = last_seq + 1
        else:
            new_seq = 1
        
        return f"CASE-{date_str}-{new_seq:04d}"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.case_number:
            self.case_number = self.generate_case_number()
    
    def to_dict(self):
        return {
            'id': self.id,
            'case_number': self.case_number,
            'title': self.title,
            'status': self.status,
            'severity_global': self.severity_global,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Asset(db.Model):
    """Modelo de activos (equipos)"""
    __tablename__ = 'assets'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), unique=True, nullable=False)
    unit = db.Column(db.String(100))
    hostname = db.Column(db.String(100), default="---")
    os = db.Column(db.String(100))
    source_ip = db.Column(db.String(45), nullable=False)  # Soporta IPv4 e IPv6
    mac = db.Column(db.String(17), default="---")  # Formato MAC: XX:XX:XX:XX:XX:XX
    user = db.Column(db.String(100), default="---")
    firewall = db.Column(db.String(100))
    antimalware = db.Column(db.String(100))
    
    __table_args__ = (
        Index('idx_asset_case', 'case_id'),
    )
    
    def validate_mac(self):
        """Valida formato MAC address"""
        if self.mac and self.mac != "---":
            mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if not mac_pattern.match(self.mac):
                raise ValueError(f"Formato MAC inválido: {self.mac}")


class Contact(db.Model):
    """Modelo de contactos"""
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), unique=True, nullable=False)
    responsible_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone_mobile = db.Column(db.String(20), default="---")
    phone_internal = db.Column(db.String(20))
    contact_date = db.Column(db.DateTime, default=datetime.utcnow)
    communication_details = db.Column(db.Text)
    contacted = db.Column(db.Boolean, default=False)
    
    __table_args__ = (
        Index('idx_contact_case', 'case_id'),
    )


class IOC(db.Model):
    """Modelo de Indicators of Compromise"""
    __tablename__ = 'iocs'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False, index=True)  # IP o dominio
    type = db.Column(db.String(20), nullable=False)  # ip/domain
    direction = db.Column(db.String(20), nullable=False)  # source/destination
    is_internal = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    analyses = db.relationship('IOCAnalysis', backref='ioc', uselist=False, cascade='all, delete-orphan')
    
    __table_args__ = (
        Index('idx_ioc_case_value', 'case_id', 'value'),
        UniqueConstraint('case_id', 'value', name='unique_ioc_per_case'),
    )
    
    def validate_ip(self):
        """Validación básica de IP"""
        if self.type == 'ip':
            # Patrón simple para IPv4
            ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
            if not ipv4_pattern.match(self.value):
                # Podríamos agregar validación IPv6 aquí
                raise ValueError(f"Formato IP inválido: {self.value}")


class IOCAnalysis(db.Model):
    """Modelo de análisis de IOC"""
    __tablename__ = 'ioc_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    vt_score = db.Column(db.Float, default=0)  # VirusTotal (0-100)
    abuse_score = db.Column(db.Float, default=0)  # AbuseIPDB (0-100)
    greynoise_score = db.Column(db.Float, default=0)  # GreyNoise (0-100)
    ibm_score = db.Column(db.Float, default=0)  # IBM X-Force (0-100)
    consensus_percentage = db.Column(db.Float, default=0)
    final_score = db.Column(db.Float, default=0)
    classification = db.Column(db.String(50))  # malicious/suspicious/benign/unknown
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_analysis_ioc', 'ioc_id'),
        Index('idx_analysis_score', 'final_score'),
    )
    
    def to_dict(self):
        return {
            'vt_score': self.vt_score,
            'abuse_score': self.abuse_score,
            'greynoise_score': self.greynoise_score,
            'ibm_score': self.ibm_score,
            'consensus_percentage': self.consensus_percentage,
            'final_score': self.final_score,
            'classification': self.classification,
            'analyzed_at': self.analyzed_at.isoformat() if self.analyzed_at else None
        }


class IOCCache(db.Model):
    """Modelo de caché para resultados de IOC"""
    __tablename__ = 'ioc_cache'
    
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False, index=True)  # IP o dominio
    source = db.Column(db.String(50), nullable=False)  # virustotal, abuseipdb, etc.
    raw_score = db.Column(db.Float)
    normalized_score = db.Column(db.Float)  # Normalizado a 0-100
    classification = db.Column(db.String(50))
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    __table_args__ = (
        UniqueConstraint('value', 'source', name='unique_cache_entry'),
        Index('idx_cache_expires', 'expires_at'),
    )
    
    def is_expired(self):
        """Verifica si la entrada de caché ha expirado"""
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self):
        return {
            'value': self.value,
            'source': self.source,
            'normalized_score': self.normalized_score,
            'classification': self.classification,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None
        }


# Comandos para crear base de datos (para incluir en README o script separado)
"""
# Para crear la base de datos en desarrollo:
from app.factory import create_app
from app.extensions import db
from infrastructure.database import models

app = create_app('development')
with app.app_context():
    db.create_all()
    print("Base de datos creada exitosamente")

# Para migrar a PostgreSQL:
# 1. Cambiar APP_MODE=server en .env
# 2. Configurar DATABASE_URL=postgresql://user:pass@localhost/soc_case_db
# 3. Ejecutar el mismo comando de creación
"""