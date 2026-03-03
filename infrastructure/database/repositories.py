# infrastructure/database/repositories.py
from app.extensions import db
from infrastructure.database.models import Case, Asset, Contact, IOC, IOCAnalysis, IOCCache
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.exc import IntegrityError
import traceback

class CaseRepository:
    """Repositorio para operaciones con casos"""
    
    def create(self, **kwargs) -> Case:
        """Crear un nuevo caso"""
        try:
            case = Case(**kwargs)
            db.session.add(case)
            db.session.flush()  # Para obtener el ID sin commit
            return case
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error creating case: {str(e)}")
    
    def get_by_id(self, case_id: int) -> Optional[Case]:
        """Obtener caso por ID"""
        return Case.query.get(case_id)
    
    def get_by_number(self, case_number: str) -> Optional[Case]:
        """Obtener caso por número"""
        return Case.query.filter_by(case_number=case_number).first()
    
    def update(self, case_id: int, **kwargs) -> Optional[Case]:
        """Actualizar caso existente"""
        case = self.get_by_id(case_id)
        if case:
            for key, value in kwargs.items():
                if hasattr(case, key):
                    setattr(case, key, value)
            case.updated_at = datetime.utcnow()
            db.session.flush()
        return case
    
    def delete(self, case_id: int) -> bool:
        """Eliminar caso (soft delete no implementado)"""
        case = self.get_by_id(case_id)
        if case:
            db.session.delete(case)
            db.session.flush()
            return True
        return False
    
    def list_all(self, status: Optional[str] = None) -> List[Case]:
        """Listar casos, opcionalmente filtrados por estado"""
        query = Case.query
        if status:
            query = query.filter_by(status=status)
        return query.order_by(Case.created_at.desc()).all()
    
    def close_case(self, case_id: int, conclusion: str) -> Optional[Case]:
        """Cerrar un caso con conclusión"""
        if not conclusion or not conclusion.strip():
            raise ValueError("Conclusion is required to close a case")
        
        case = self.get_by_id(case_id)
        if case:
            case.status = 'closed'
            case.conclusion = conclusion
            case.updated_at = datetime.utcnow()
            db.session.flush()
        return case


class AssetRepository:
    """Repositorio para operaciones con assets"""
    
    def create(self, case_id: int, **kwargs) -> Asset:
        """Crear un asset para un caso"""
        # Verificar que no exista ya un asset para este caso
        existing = Asset.query.filter_by(case_id=case_id).first()
        if existing:
            raise ValueError(f"Case {case_id} already has an asset")
        
        asset = Asset(case_id=case_id, **kwargs)
        db.session.add(asset)
        db.session.flush()
        return asset
    
    def get_by_case(self, case_id: int) -> Optional[Asset]:
        """Obtener asset por ID de caso"""
        return Asset.query.filter_by(case_id=case_id).first()
    
    def update(self, case_id: int, **kwargs) -> Optional[Asset]:
        """Actualizar asset de un caso"""
        asset = self.get_by_case(case_id)
        if asset:
            for key, value in kwargs.items():
                if hasattr(asset, key):
                    setattr(asset, key, value)
            db.session.flush()
        return asset


class ContactRepository:
    """Repositorio para operaciones con contactos"""
    
    def create(self, case_id: int, **kwargs) -> Contact:
        """Crear un contacto para un caso"""
        # Verificar que no exista ya un contacto para este caso
        existing = Contact.query.filter_by(case_id=case_id).first()
        if existing:
            raise ValueError(f"Case {case_id} already has a contact")
        
        contact = Contact(case_id=case_id, **kwargs)
        db.session.add(contact)
        db.session.flush()
        return contact
    
    def get_by_case(self, case_id: int) -> Optional[Contact]:
        """Obtener contacto por ID de caso"""
        return Contact.query.filter_by(case_id=case_id).first()
    
    def update(self, case_id: int, **kwargs) -> Optional[Contact]:
        """Actualizar contacto de un caso"""
        contact = self.get_by_case(case_id)
        if contact:
            for key, value in kwargs.items():
                if hasattr(contact, key):
                    setattr(contact, key, value)
            db.session.flush()
        return contact


class IOCRepository:
    """Repositorio para operaciones con IOCs"""
    
    def create(self, case_id: int, value: str, type: str, 
               direction: str, is_internal: bool = False) -> IOC:
        """Crear un nuevo IOC"""
        # Validar que no exista duplicado en el mismo caso
        existing = IOC.query.filter_by(case_id=case_id, value=value).first()
        if existing:
            raise ValueError(f"IOC {value} already exists in case {case_id}")
        
        # Validar que solo haya una IP source por caso
        if direction == 'source':
            source_exists = IOC.query.filter_by(
                case_id=case_id, direction='source'
            ).first()
            if source_exists:
                raise ValueError(f"Case {case_id} already has a source IP")
        
        ioc = IOC(
            case_id=case_id,
            value=value,
            type=type,
            direction=direction,
            is_internal=is_internal
        )
        
        # Validar formato según tipo
        if type == 'ip':
            ioc.validate_ip()
        
        db.session.add(ioc)
        db.session.flush()
        return ioc
    
    def get_by_case(self, case_id: int, direction: Optional[str] = None) -> List[IOC]:
        """Obtener IOCs de un caso"""
        query = IOC.query.filter_by(case_id=case_id)
        if direction:
            query = query.filter_by(direction=direction)
        return query.all()
    
    def get_by_id(self, ioc_id: int) -> Optional[IOC]:
        """Obtener IOC por ID"""
        return IOC.query.get(ioc_id)
    
    def get_by_value(self, value: str, case_id: Optional[int] = None) -> List[IOC]:
        """Buscar IOC por valor"""
        query = IOC.query.filter_by(value=value)
        if case_id:
            query = query.filter_by(case_id=case_id)
        return query.all()
    
    def get_destination_iocs(self, case_id: int) -> List[IOC]:
        """Obtener solo IOCs de destino para análisis"""
        return IOC.query.filter_by(
            case_id=case_id, 
            direction='destination'
        ).all()
    
    def delete(self, ioc_id: int) -> bool:
        """Eliminar un IOC"""
        ioc = self.get_by_id(ioc_id)
        if ioc:
            db.session.delete(ioc)
            db.session.flush()
            return True
        return False


class IOCAnalysisRepository:
    """Repositorio para operaciones con análisis de IOC"""
    
    def create(self, ioc_id: int, analysis_data: Dict[str, Any]) -> IOCAnalysis:
        """Crear o actualizar análisis para un IOC"""
        existing = IOCAnalysis.query.filter_by(ioc_id=ioc_id).first()
        
        if existing:
            # Actualizar existente
            for key, value in analysis_data.items():
                if hasattr(existing, key):
                    setattr(existing, key, value)
            existing.analyzed_at = datetime.utcnow()
            analysis = existing
        else:
            # Crear nuevo
            analysis = IOCAnalysis(ioc_id=ioc_id, **analysis_data)
            db.session.add(analysis)
        
        db.session.flush()
        return analysis
    
    def get_by_ioc(self, ioc_id: int) -> Optional[IOCAnalysis]:
        """Obtener análisis por IOC ID"""
        return IOCAnalysis.query.filter_by(ioc_id=ioc_id).first()
    
    def get_by_case(self, case_id: int) -> List[IOCAnalysis]:
        """Obtener todos los análisis de un caso"""
        return (IOCAnalysis.query
                .join(IOC, IOC.id == IOCAnalysis.ioc_id)
                .filter(IOC.case_id == case_id)
                .all())


class IOCCacheRepository:
    """Repositorio para operaciones con caché de IOC"""
    
    def get(self, value: str, source: str) -> Optional[IOCCache]:
        """Obtener entrada de caché si existe y no ha expirado"""
        cache_entry = IOCCache.query.filter_by(
            value=value, source=source
        ).first()
        
        if cache_entry and not cache_entry.is_expired():
            return cache_entry
        elif cache_entry:
            # Eliminar si está expirado
            db.session.delete(cache_entry)
            db.session.flush()
        
        return None
    
    def set(self, value: str, source: str, raw_score: float, 
            normalized_score: float, classification: str, ttl: int) -> IOCCache:
        """Guardar o actualizar entrada en caché"""
        from datetime import timedelta
        
        existing = IOCCache.query.filter_by(value=value, source=source).first()
        
        expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        
        if existing:
            existing.raw_score = raw_score
            existing.normalized_score = normalized_score
            existing.classification = classification
            existing.last_checked = datetime.utcnow()
            existing.expires_at = expires_at
            cache_entry = existing
        else:
            cache_entry = IOCCache(
                value=value,
                source=source,
                raw_score=raw_score,
                normalized_score=normalized_score,
                classification=classification,
                expires_at=expires_at
            )
            db.session.add(cache_entry)
        
        db.session.flush()
        return cache_entry
    
    def clear_expired(self) -> int:
        """Eliminar entradas expiradas"""
        expired = IOCCache.query.filter(
            IOCCache.expires_at < datetime.utcnow()
        ).all()
        
        count = len(expired)
        for entry in expired:
            db.session.delete(entry)
        
        if count > 0:
            db.session.flush()
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas de caché"""
        total = IOCCache.query.count()
        expired = IOCCache.query.filter(
            IOCCache.expires_at < datetime.utcnow()
        ).count()
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'active_entries': total - expired
        }


# Función de utilidad para commit transaccional
def commit_transaction():
    """Realizar commit de la transacción actual"""
    try:
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        raise ValueError(f"Database integrity error: {str(e)}")
    except Exception as e:
        db.session.rollback()
        raise ValueError(f"Database error: {str(e)}")


# Función para inicializar base de datos
def init_database(app):
    """Inicializar base de datos (crear tablas)"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully")
