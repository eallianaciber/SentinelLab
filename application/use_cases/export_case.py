# application/use_cases/export_case.py
from infrastructure.database.repositories import CaseRepository, IOCRepository
from infrastructure.exporters.markdown_exporter import MarkdownExporter
from infrastructure.logging.logger import get_logger
from typing import Optional
import os

logger = get_logger('use_cases')

class ExportCaseUseCase:
    """Caso de uso para exportar un caso a Markdown"""
    
    def __init__(self, case_repo: CaseRepository, ioc_repo: IOCRepository, 
                 exporter: Optional[MarkdownExporter] = None):
        self.case_repo = case_repo
        self.ioc_repo = ioc_repo
        self.exporter = exporter or MarkdownExporter()
    
    def execute(self, case_id: int, output_dir: Optional[str] = None) -> str:
        """
        Exportar caso a archivo Markdown
        Returns: Ruta del archivo generado
        """
        logger.info(f"Exporting case {case_id}")
        
        # Obtener caso
        case = self.case_repo.get_by_id(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        # Verificar que tenga IOCs destino
        destination_iocs = self.ioc_repo.get_destination_iocs(case_id)
        if not destination_iocs:
            logger.warning(f"Case {case_id} has no destination IOCs")
        
        try:
            # Exportar
            filepath = self.exporter.export(case, output_dir)
            
            logger.info(f"Case {case.case_number} exported to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting case {case_id}: {str(e)}")
            raise
    
    def get_export_path(self, case_id: int) -> Optional[str]:
        """
        Obtener ruta del archivo exportado si existe
        """
        case = self.case_repo.get_by_id(case_id)
        if not case:
            return None
        
        filename = self.exporter.generate_filename(case.case_number, case.title)
        
        # Buscar en directorio de exports
        exports_dir = self.exporter.exports_folder
        filepath = os.path.join(exports_dir, filename)
        
        if os.path.exists(filepath):
            return filepath
        
        return None
