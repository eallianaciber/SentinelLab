# plugins/server_mode/postgres_models.py
"""
Modelos específicos para PostgreSQL
Extienden o reemplazan los modelos base cuando APP_MODE=server
"""
from app.extensions import db
from sqlalchemy.dialects.postgresql import JSONB, INET, MACADDR, UUID
from datetime import datetime
import uuid

class ServerCase(db.Model):
    """
    Modelo de casos optimizado para PostgreSQL
    Usa tipos específicos de PostgreSQL y características avanzadas
    """
    __tablename__ = 'server_cases'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    corrective_action = db.Column(db.Text)
    conclusion = db.Column(db.Text)
    severity_global = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='open')
    
    # Metadatos adicionales para server mode
    metadata = db.Column(JSONB, default={})  # Campo flexible para metadatos
    tags = db.Column(JSONB, default=[])  # Array de tags
    custom_fields = db.Column(JSONB, default={})  # Campos personalizables
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(100))  # Usuario que creó
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.String(100))  # Último usuario que modificó
    
    # Índices GIN para búsqueda en JSON
    __table_args__ = (
        db.Index('idx_case_metadata_gin', metadata, postgresql_using='gin'),
        db.Index('idx_case_tags_gin', tags, postgresql_using='gin'),
    )


class ServerAsset(db.Model):
    """Modelo de assets optimizado para PostgreSQL"""
    __tablename__ = 'server_assets'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey('server_cases.id', ondelete='CASCADE'), 
                        nullable=False, unique=True)
    
    # Tipos específicos de PostgreSQL
    unit = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    os = db.Column(db.String(100))
    source_ip = db.Column(INET, nullable=False)  # Tipo INET nativo
    mac = db.Column(MACADDR)  # Tipo MACADDR nativo
    user = db.Column(db.String(100))
    firewall = db.Column(db.String(100))
    antimalware = db.Column(db.String(100))
    
    # Metadatos
    asset_metadata = db.Column(JSONB, default={})
    discovered_services = db.Column(JSONB, default=[])
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ServerContact(db.Model):
    """Modelo de contactos optimizado para PostgreSQL"""
    __tablename__ = 'server_contacts'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey('server_cases.id', ondelete='CASCADE'),
                        nullable=False, unique=True)
    
    responsible_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    phone_mobile = db.Column(db.String(20))
    phone_internal = db.Column(db.String(20))
    contact_date = db.Column(db.DateTime, default=datetime.utcnow)
    communication_details = db.Column(db.Text)
    contacted = db.Column(db.Boolean, default=False)
    
    # Historial de comunicaciones
    communication_history = db.Column(JSONB, default=[])
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ServerIOC(db.Model):
    """Modelo de IOCs optimizado para PostgreSQL"""
    __tablename__ = 'server_iocs'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey('server_cases.id', ondelete='CASCADE'),
                        nullable=False)
    
    value = db.Column(db.String(255), nullable=False)
    value_type = db.Column(db.String(20), nullable=False)  # Usar 'value_type' en lugar de 'type'
    direction = db.Column(db.String(20), nullable=False)
    is_internal = db.Column(db.Boolean, default=False)
    
    # Información adicional
    whois_info = db.Column(JSONB, default={})
    geolocation = db.Column(JSONB, default={})
    related_domains = db.Column(JSONB, default=[])
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_server_ioc_value', value),
        db.UniqueConstraint('case_id', 'value', name='uq_server_ioc_case_value'),
        db.Index('idx_server_ioc_value_gin', value, postgresql_using='gin'),
    )


class ServerIOCAnalysis(db.Model):
    """Modelo de análisis de IOCs optimizado para PostgreSQL"""
    __tablename__ = 'server_ioc_analysis'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id = db.Column(UUID(as_uuid=True), db.ForeignKey('server_iocs.id', ondelete='CASCADE'),
                       nullable=False, unique=True)
    
    vt_score = db.Column(db.Float, default=0)
    abuse_score = db.Column(db.Float, default=0)
    greynoise_score = db.Column(db.Float, default=0)
    ibm_score = db.Column(db.Float, default=0)
    
    # Análisis detallado
    vt_details = db.Column(JSONB, default={})
    abuse_details = db.Column(JSONB, default={})
    greynoise_details = db.Column(JSONB, default={})
    ibm_details = db.Column(JSONB, default={})
    
    consensus_percentage = db.Column(db.Float, default=0)
    final_score = db.Column(db.Float, default=0)
    classification = db.Column(db.String(50))
    
    # Historial de análisis
    analysis_history = db.Column(JSONB, default=[])
    
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow)
    analyzed_by = db.Column(db.String(100))  # Usuario/script que analizó


class ServerIOCCache(db.Model):
    """Modelo de caché optimizado para PostgreSQL"""
    __tablename__ = 'server_ioc_cache'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = db.Column(db.String(255), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    
    raw_score = db.Column(db.Float)
    normalized_score = db.Column(db.Float)
    classification = db.Column(db.String(50))
    
    # Respuesta completa de la API
    full_response = db.Column(JSONB, default={})
    
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('value', 'source', name='uq_server_cache_entry'),
        db.Index('idx_server_cache_expires', expires_at),
        db.Index('idx_server_cache_value_gin', value, postgresql_using='gin'),
    )


# Vistas materializadas para reporting
class CaseSummaryMaterialized(db.Model):
    """
    Vista materializada para resúmenes de casos
    Solo en PostgreSQL
    """
    __tablename__ = 'case_summary_mv'
    __table_args__ = {'info': {'is_materialized': True}}
    
    id = db.Column(UUID(as_uuid=True), primary_key=True)
    case_number = db.Column(db.String(50))
    title = db.Column(db.String(200))
    status = db.Column(db.String(20))
    severity = db.Column(db.Integer)
    created_date = db.Column(db.Date)
    ioc_count = db.Column(db.Integer)
    max_score = db.Column(db.Float)
    avg_score = db.Column(db.Float)
    classification_summary = db.Column(JSONB)


# Funciones para migración desde SQLite
def migrate_from_sqlite_to_postgres():
    """
    Script de migración de SQLite a PostgreSQL
    """
    return """
    -- Script de migración (para ejecutar manualmente)
    
    -- 1. Exportar datos de SQLite a CSV
    .mode csv
    .output cases_export.csv
    SELECT * FROM cases;
    
    -- 2. Importar a PostgreSQL
    COPY server_cases (id, case_number, title, description, corrective_action, 
                       conclusion, severity_global, status, created_at, updated_at)
    FROM 'cases_export.csv' DELIMITER ',' CSV HEADER;
    
    -- 3. Actualizar secuencias
    SELECT setval('server_cases_id_seq', (SELECT MAX(id) FROM server_cases));
    """