# application/use_cases/close_case.py
from infrastructure.database.repositories import CaseRepository, commit_transaction
from infrastructure.logging.logger import get_logger
from application.dto import CaseDTO

logger = get_logger('use_cases')

class CloseCaseUseCase:
    """Caso de uso para cerrar un caso"""
    
    def __init__(self, case_repo: CaseRepository):
        self.case_repo = case_repo
    
    def execute(self, case_id: int, conclusion: str) -> CaseDTO:
        """
        Cerrar un caso con conclusión
        """
        logger.info(f"Closing case {case_id}")
        
        # Validar conclusión
        if not conclusion or not conclusion.strip():
            raise ValueError("Conclusion is required to close a case")
        
        # Obtener caso
        case = self.case_repo.get_by_id(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        # Verificar que no esté ya cerrado
        if case.status == 'closed':
            raise ValueError(f"Case {case_id} is already closed")
        
        # Cerrar caso
        closed_case = self.case_repo.close_case(case_id, conclusion.strip())
        
        if not closed_case:
            raise ValueError(f"Failed to close case {case_id}")
        
        commit_transaction()
        
        logger.info(f"Case {case.case_number} closed successfully")
        
        return CaseDTO.from_model(closed_case)