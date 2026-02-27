# infrastructure/exporters/markdown_exporter.py
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import re
from datetime import datetime
from typing import Optional, Dict, Any
from infrastructure.database.models import Case, Asset, Contact, IOC, IOCAnalysis
from infrastructure.logging.logger import get_logger
import unicodedata

logger = get_logger('exporters')

class MarkdownExporter:
    """
    Exportador de casos a formato Markdown usando plantillas Jinja2
    """
    
    def __init__(self, template_folder: str = None):
        """
        Inicializar exportador con carpeta de plantillas
        Args:
            template_folder: Ruta a la carpeta de plantillas (por defecto: ./templates)
        """
        if template_folder is None:
            # Obtener ruta absoluta al directorio de este archivo
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_folder = os.path.join(current_dir, 'templates')
        
        self.template_folder = template_folder
        self.env = Environment(
            loader=FileSystemLoader(template_folder),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Crear carpeta de exports si no existe
        self.exports_folder = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'exports'
        )
        os.makedirs(self.exports_folder, exist_ok=True)
        
        logger.info(f"MarkdownExporter initialized with template folder: {template_folder}")
        logger.info(f"Exports will be saved to: {self.exports_folder}")
    
    def sanitize_filename(self, title: str) -> str:
        """
        Sanitizar título para uso en nombre de archivo
        """
        # Normalizar caracteres Unicode
        title = unicodedata.normalize('NFKD', title).encode('ASCII', 'ignore').decode('ASCII')
        
        # Reemplazar espacios y caracteres no válidos
        title = re.sub(r'[^\w\s-]', '', title.lower())
        title = re.sub(r'[-\s]+', '_', title)
        
        # Limitar longitud
        return title[:50].strip('_')
    
    def generate_filename(self, case_number: str, title: str) -> str:
        """
        Generar nombre de archivo: {case_number}_{titulo_sanitizado}.md
        """
        sanitized_title = self.sanitize_filename(title)
        return f"{case_number}_{sanitized_title}.md"
    
    def prepare_context(self, case: Case) -> Dict[str, Any]:
        """
        Preparar contexto para la plantilla
        """
        # Obtener relaciones
        asset = Asset.query.filter_by(case_id=case.id).first()
        contact = Contact.query.filter_by(case_id=case.id).first()
        
        # Obtener IOCs separados por dirección
        iocs = IOC.query.filter_by(case_id=case.id).all()
        source_ioc = next((i for i in iocs if i.direction == 'source'), None)
        destination_iocs = [i for i in iocs if i.direction == 'destination']
        
        # Cargar análisis para cada IOC destino
        for ioc in destination_iocs:
            analysis = IOCAnalysis.query.filter_by(ioc_id=ioc.id).first()
            if analysis:
                # Convertir a diccionario para la plantilla
                ioc.analyses = {
                    'vt_score': analysis.vt_score,
                    'abuse_score': analysis.abuse_score,
                    'greynoise_score': analysis.greynoise_score,
                    'ibm_score': analysis.ibm_score,
                    'final_score': analysis.final_score,
                    'classification': analysis.classification,
                    'sources_contributing': self._get_sources_contributing(analysis)
                }
        
        return {
            'case': case,
            'asset': asset,
            'contact': contact,
            'source_ioc': source_ioc,
            'destination_iocs': destination_iocs,
            'generation_date': datetime.utcnow()
        }
    
    def _get_sources_contributing(self, analysis: IOCAnalysis) -> list:
        """
        Obtener lista de fuentes que contribuyeron al análisis
        """
        sources = []
        if analysis.vt_score > 0:
            sources.append('VirusTotal')
        if analysis.abuse_score > 0:
            sources.append('AbuseIPDB')
        if analysis.greynoise_score > 0:
            sources.append('GreyNoise')
        if analysis.ibm_score > 0:
            sources.append('IBM X-Force')
        return sources
    
    def export(self, case: Case, output_dir: Optional[str] = None) -> str:
        """
        Exportar caso a archivo Markdown
        Args:
            case: Instancia del caso a exportar
            output_dir: Directorio de salida (opcional)
        Returns:
            Ruta completa al archivo generado
        """
        try:
            # Preparar contexto
            context = self.prepare_context(case)
            
            # Cargar y renderizar plantilla
            template = self.env.get_template('case_template.md.j2')
            markdown_content = template.render(**context)
            
            # Generar nombre de archivo
            filename = self.generate_filename(case.case_number, case.title)
            
            # Determinar directorio de salida
            if output_dir is None:
                output_dir = self.exports_folder
            else:
                os.makedirs(output_dir, exist_ok=True)
            
            # Guardar archivo
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            logger.info(f"Case {case.case_number} exported to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting case {case.case_number}: {str(e)}")
            raise
    
    def export_batch(self, cases: list, output_dir: Optional[str] = None) -> list:
        """
        Exportar múltiples casos
        Args:
            cases: Lista de casos a exportar
            output_dir: Directorio de salida (opcional)
        Returns:
            Lista de rutas a archivos generados
        """
        exported_files = []
        errors = []
        
        for case in cases:
            try:
                filepath = self.export(case, output_dir)
                exported_files.append(filepath)
            except Exception as e:
                errors.append({'case': case.case_number, 'error': str(e)})
        
        if errors:
            logger.warning(f"Batch export completed with {len(errors)} errors: {errors}")
        
        return exported_files
    
    def get_template_info(self) -> Dict[str, Any]:
        """
        Obtener información sobre la plantilla
        """
        try:
            template = self.env.get_template('case_template.md.j2')
            return {
                'template_name': 'case_template.md.j2',
                'template_path': os.path.join(self.template_folder, 'case_template.md.j2'),
                'exports_folder': self.exports_folder,
                'available_filters': list(self.env.filters.keys()),
                'available_tests': list(self.env.tests.keys())
            }
        except Exception as e:
            return {'error': str(e)}
    
    def validate_template(self) -> bool:
        """
        Validar que la plantilla existe y es válida
        """
        try:
            template_path = os.path.join(self.template_folder, 'case_template.md.j2')
            if not os.path.exists(template_path):
                logger.error(f"Template not found: {template_path}")
                return False
            
            # Intentar cargar la plantilla
            self.env.get_template('case_template.md.j2')
            return True
            
        except Exception as e:
            logger.error(f"Template validation failed: {str(e)}")
            return False


# Ejemplo de uso (para pruebas)
if __name__ == '__main__':
    from app.factory import create_app
    from app.extensions import db
    from infrastructure.database.models import Case
    
    # Crear contexto de aplicación
    app = create_app('development')
    
    with app.app_context():
        # Obtener un caso de ejemplo
        case = Case.query.first()
        
        if case:
            # Crear exportador
            exporter = MarkdownExporter()
            
            # Validar plantilla
            if exporter.validate_template():
                # Exportar caso
                filepath = exporter.export(case)
                print(f"✅ Case exported to: {filepath}")
                
                # Mostrar información de plantilla
                info = exporter.get_template_info()
                print(f"📄 Template info: {info}")
            else:
                print("❌ Template validation failed")
        else:
            print("⚠️ No cases found in database")