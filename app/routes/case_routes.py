# app/routes/case_routes.py (versión completa con server mode)
from flask import Blueprint, request, jsonify, render_template_string, g, current_app
from application.use_cases.create_case import CreateCaseUseCase
from application.use_cases.add_ioc import AddIOCUseCase
from application.use_cases.analyze_iocs import AnalyzeIOCsUseCase
from application.use_cases.export_case import ExportCaseUseCase
from application.use_cases.close_case import CloseCaseUseCase
from application.dto import CreateCaseRequest
from infrastructure.database.repositories import CaseRepository, IOCRepository, commit_transaction
from infrastructure.logging.logger import get_logger
import traceback
import os

# Importar autenticación solo si está en server mode
APP_MODE = os.getenv('APP_MODE', 'local')
if APP_MODE == 'server':
    from plugins.server_mode.auth import login_required, role_required, auth_manager

case_bp = Blueprint('cases', __name__)
logger = get_logger('routes')

# HTML Template mejorado
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SOC Case Manager - {{ mode|upper }} Mode</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h1 { 
            color: #333; 
            margin-bottom: 10px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .mode-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .mode-local { background: #28a745; color: white; }
        .mode-server { background: #dc3545; color: white; }
        .form-section { 
            background: #f8f9fa; 
            padding: 20px; 
            margin-bottom: 20px; 
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        .form-section h3 { 
            color: #495057; 
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        .form-group { margin-bottom: 15px; }
        label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: 600; 
            color: #495057;
            font-size: 0.9em;
        }
        input[type=text], input[type=email], textarea, select { 
            width: 100%; 
            padding: 10px; 
            border: 1px solid #ced4da; 
            border-radius: 4px; 
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type=text]:focus, input[type=email]:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        .ioc-list { 
            margin: 10px 0; 
            max-height: 300px;
            overflow-y: auto;
            padding: 10px;
            background: white;
            border-radius: 4px;
        }
        .ioc-item { 
            display: flex; 
            gap: 10px; 
            margin-bottom: 10px;
            align-items: center;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
        }
        .ioc-item input { flex: 1; }
        .btn { 
            padding: 10px 20px; 
            background: #667eea; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 14px;
            font-weight: 600;
            transition: background 0.3s;
        }
        .btn:hover { background: #5a67d8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
        .result { 
            margin-top: 30px; 
            padding: 20px; 
            background: #e8f4fd; 
            border-radius: 5px;
            border-left: 4px solid #17a2b8;
            display: none;
        }
        .result pre {
            background: white;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 12px;
            margin-top: 10px;
        }
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .contact-fields {
            display: none;
            margin-top: 15px;
            padding: 15px;
            background: #e9ecef;
            border-radius: 4px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            font-size: 12px;
            color: #6c757d;
            text-transform: uppercase;
        }
        .auth-bar {
            background: #343a40;
            color: white;
            padding: 10px 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
    </style>
</head>
<body>
    <div class="container">
        {% if mode == 'server' %}
        <div class="auth-bar">
            <span>🔐 Server Mode - Autenticación Requerida</span>
            <div>
                <span id="userDisplay">No autenticado</span>
                <button class="btn btn-sm" onclick="showLogin()" id="loginBtn">Iniciar Sesión</button>
                <button class="btn btn-sm btn-danger" onclick="logout()" id="logoutBtn" style="display:none;">Cerrar Sesión</button>
            </div>
        </div>
        {% endif %}
        
        <h1>
            SOC Case Manager 
            <span class="mode-badge mode-{{ mode }}">{{ mode|upper }} MODE</span>
        </h1>
        
        <!-- Login Modal (solo server mode) -->
        {% if mode == 'server' %}
        <div id="loginModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000;">
            <div style="background:white; width:400px; margin:100px auto; padding:30px; border-radius:10px;">
                <h3>Iniciar Sesión</h3>
                <div class="form-group">
                    <label>Usuario</label>
                    <input type="text" id="loginUsername" placeholder="usuario">
                </div>
                <div class="form-group">
                    <label>Contraseña</label>
                    <input type="password" id="loginPassword" placeholder="contraseña">
                </div>
                <button class="btn" onclick="doLogin()">Ingresar</button>
                <button class="btn btn-danger" onclick="hideLogin()">Cancelar</button>
            </div>
        </div>
        {% endif %}
        
        <!-- Stats Dashboard -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalCases">0</div>
                <div class="stat-label">Casos Totales</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="openCases">0</div>
                <div class="stat-label">Casos Abiertos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="closedCases">0</div>
                <div class="stat-label">Casos Cerrados</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalIOCs">0</div>
                <div class="stat-label">IOCs Analizados</div>
            </div>
        </div>
        
        <form id="caseForm">
            <div class="form-section">
                <h3>📋 Información Básica</h3>
                <div class="form-group">
                    <label>Título del Caso *</label>
                    <input type="text" name="title" placeholder="Ej: Investigación de actividad sospechosa" required>
                </div>
            </div>
            
            <div class="form-section">
                <h3>🌐 IPs</h3>
                <div class="form-group">
                    <label>IP Origen (única) *</label>
                    <input type="text" name="source_ip" placeholder="192.168.1.100" required>
                </div>
                
                <div class="form-group">
                    <label>IPs Destino (mínimo una para análisis) *</label>
                    <div id="destinationIps" class="ioc-list">
                        <div class="ioc-item">
                            <input type="text" name="destination_ips[]" placeholder="8.8.8.8" required>
                            <button type="button" class="btn btn-danger btn-sm" onclick="removeIoc(this)">✕</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-success btn-sm" onclick="addIoc()">+ Agregar IP Destino</button>
                </div>
            </div>
            
            <div class="form-section">
                <h3>📝 Descripción</h3>
                <div class="form-group">
                    <textarea name="description" rows="4" placeholder="Describa el incidente en detalle..."></textarea>
                </div>
            </div>
            
            <div class="form-section">
                <h3>💻 Datos del Equipo</h3>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                    <div class="form-group">
                        <label>Hostname</label>
                        <input type="text" name="hostname" placeholder="SRV-WEB-01">
                    </div>
                    <div class="form-group">
                        <label>Sistema Operativo</label>
                        <input type="text" name="os" placeholder="Windows Server 2019">
                    </div>
                    <div class="form-group">
                        <label>Dirección MAC</label>
                        <input type="text" name="mac" placeholder="00:1A:2B:3C:4D:5E">
                    </div>
                    <div class="form-group">
                        <label>Usuario</label>
                        <input type="text" name="user" placeholder="juan.perez">
                    </div>
                    <div class="form-group">
                        <label>Firewall</label>
                        <input type="text" name="firewall" placeholder="Fortinet FG-100D">
                    </div>
                    <div class="form-group">
                        <label>Antimalware</label>
                        <input type="text" name="antimalware" placeholder="SentinelOne">
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <h3>🔧 Acción Correctiva</h3>
                <div class="form-group">
                    <textarea name="corrective_action" rows="3" placeholder="Acciones tomadas para mitigar el incidente..."></textarea>
                </div>
            </div>
            
            <div class="form-section">
                <h3>📞 Contacto</h3>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="enable_contact" onchange="toggleContact(this)">
                        Agregar información de contacto
                    </label>
                </div>
                
                <div id="contactFields" class="contact-fields">
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                        <div class="form-group">
                            <label>Nombre Responsable</label>
                            <input type="text" name="responsible_name" placeholder="Juan Pérez">
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" name="email" placeholder="juan@empresa.com">
                        </div>
                        <div class="form-group">
                            <label>Teléfono Móvil</label>
                            <input type="text" name="phone_mobile" placeholder="+56 9 1234 5678">
                        </div>
                        <div class="form-group">
                            <label>Teléfono Interno</label>
                            <input type="text" name="phone_internal" placeholder="1234">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Detalles de Comunicación</label>
                        <textarea name="communication_details" rows="2" placeholder="Detalles de la comunicación..."></textarea>
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <h3>✅ Conclusión</h3>
                <div class="form-group">
                    <textarea name="conclusion" rows="3" placeholder="Conclusión del caso (requerida para cerrar)..."></textarea>
                </div>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button type="submit" class="btn">💾 Guardar y Analizar</button>
                <button type="button" class="btn btn-success" onclick="exportCase()">📤 Exportar</button>
                <button type="button" class="btn btn-danger" onclick="closeCase()">🔒 Cerrar Caso</button>
            </div>
        </form>
        
        <div id="result" class="result">
            <h3>📊 Resultado del Análisis</h3>
            <div id="resultContent"></div>
        </div>
    </div>
    
    <script>
        let currentCaseId = null;
        let authToken = localStorage.getItem('authToken');
        
        {% if mode == 'server' %}
        // Actualizar UI según autenticación
        function updateAuthUI() {
            if (authToken) {
                document.getElementById('loginBtn').style.display = 'none';
                document.getElementById('logoutBtn').style.display = 'inline-block';
                
                // Obtener información del usuario
                fetch('/auth/me', {
                    headers: {'Authorization': 'Bearer ' + authToken}
                })
                .then(res => res.json())
                .then(user => {
                    document.getElementById('userDisplay').textContent = 
                        `👤 ${user.username} (${user.role})`;
                });
            } else {
                document.getElementById('loginBtn').style.display = 'inline-block';
                document.getElementById('logoutBtn').style.display = 'none';
                document.getElementById('userDisplay').textContent = 'No autenticado';
            }
        }
        
        function showLogin() {
            document.getElementById('loginModal').style.display = 'block';
        }
        
        function hideLogin() {
            document.getElementById('loginModal').style.display = 'none';
        }
        
        function doLogin() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            fetch('/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            })
            .then(res => res.json())
            .then(data => {
                if (data.token) {
                    authToken = data.token;
                    localStorage.setItem('authToken', authToken);
                    hideLogin();
                    updateAuthUI();
                    loadStats();
                } else {
                    alert('Error de autenticación');
                }
            });
        }
        
        function logout() {
            authToken = null;
            localStorage.removeItem('authToken');
            updateAuthUI();
        }
        
        // Headers con autenticación
        function getHeaders() {
            const headers = {'Content-Type': 'application/json'};
            if (authToken) {
                headers['Authorization'] = 'Bearer ' + authToken;
            }
            return headers;
        }
        {% else %}
        function getHeaders() {
            return {'Content-Type': 'application/json'};
        }
        {% endif %}
        
        // Funciones del formulario
        function addIoc() {
            const container = document.getElementById('destinationIps');
            const div = document.createElement('div');
            div.className = 'ioc-item';
            div.innerHTML = '<input type="text" name="destination_ips[]" placeholder="IP destino" required>' +
                           '<button type="button" class="btn btn-danger btn-sm" onclick="removeIoc(this)">✕</button>';
            container.appendChild(div);
        }
        
        function removeIoc(btn) {
            if (document.querySelectorAll('.ioc-item').length > 1) {
                btn.parentElement.remove();
            }
        }
        
        function toggleContact(checkbox) {
            const contactFields = document.getElementById('contactFields');
            contactFields.style.display = checkbox.checked ? 'block' : 'none';
        }
        
        // Cargar estadísticas
        function loadStats() {
            fetch('/api/cases/stats', {headers: getHeaders()})
                .then(res => res.json())
                .then(stats => {
                    document.getElementById('totalCases').textContent = stats.total_cases || 0;
                    document.getElementById('openCases').textContent = stats.open_cases || 0;
                    document.getElementById('closedCases').textContent = stats.closed_cases || 0;
                    document.getElementById('totalIOCs').textContent = stats.total_iocs || 0;
                });
        }
        
        // Exportar caso
        function exportCase() {
            if (!currentCaseId) {
                alert('Primero debe crear o seleccionar un caso');
                return;
            }
            
            fetch(`/api/cases/${currentCaseId}/export`, {headers: getHeaders()})
                .then(res => res.json())
                .then(data => {
                    if (data.file) {
                        alert(`Caso exportado a: ${data.file}`);
                    }
                });
        }
        
        // Cerrar caso
        function closeCase() {
            if (!currentCaseId) {
                alert('Primero debe crear o seleccionar un caso');
                return;
            }
            
            const conclusion = document.querySelector('textarea[name="conclusion"]').value;
            if (!conclusion) {
                alert('Se requiere conclusión para cerrar el caso');
                return;
            }
            
            fetch(`/api/cases/${currentCaseId}/close`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({conclusion})
            })
            .then(res => res.json())
            .then(data => {
                if (data.message) {
                    alert('Caso cerrado exitosamente');
                    loadStats();
                }
            });
        }
        
        // Submit del formulario
        document.getElementById('caseForm').onsubmit = async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const destinationIps = [];
            document.querySelectorAll('input[name="destination_ips[]"]').forEach(input => {
                if (input.value) destinationIps.push(input.value);
            });
            
            const data = {
                title: formData.get('title'),
                source_ip: formData.get('source_ip'),
                destination_ips: destinationIps,
                description: formData.get('description') || '',
                hostname: formData.get('hostname') || '---',
                os: formData.get('os') || '',
                mac: formData.get('mac') || '---',
                user: formData.get('user') || '---',
                firewall: formData.get('firewall') || '',
                antimalware: formData.get('antimalware') || '',
                corrective_action: formData.get('corrective_action') || '',
                enable_contact: formData.get('enable_contact') === 'on',
                responsible_name: formData.get('responsible_name') || '',
                email: formData.get('email') || '',
                phone_mobile: formData.get('phone_mobile') || '---',
                phone_internal: formData.get('phone_internal') || '',
                communication_details: formData.get('communication_details') || '',
                contacted: false,
                conclusion: formData.get('conclusion') || ''
            };
            
            try {
                const response = await fetch('/api/cases', {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    currentCaseId = result.case_id;
                    
                    const resultDiv = document.getElementById('result');
                    const resultContent = document.getElementById('resultContent');
                    
                    resultDiv.style.display = 'block';
                    resultContent.innerHTML = `
                        <div class="alert alert-success">
                            <strong>✅ Caso ${result.case_number} creado exitosamente</strong>
                        </div>
                        <h4>Resultados del Análisis:</h4>
                        <pre>${JSON.stringify(result.analysis, null, 2)}</pre>
                    `;
                    
                    loadStats();
                } else {
                    alert('Error: ' + (result.error || 'Error desconocido'));
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        };
        
        // Cargar stats al inicio
        loadStats();
        {% if mode == 'server' %}
        updateAuthUI();
        {% endif %}
    </script>
</body>
</html>
"""

# Rutas adicionales para server mode
@case_bp.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas generales"""
    try:
        from infrastructure.database.models import Case, IOC
        
        total_cases = Case.query.count()
        open_cases = Case.query.filter_by(status='open').count()
        closed_cases = Case.query.filter_by(status='closed').count()
        total_iocs = IOC.query.count()
        
        return jsonify({
            'total_cases': total_cases,
            'open_cases': open_cases,
            'closed_cases': closed_cases,
            'total_iocs': total_iocs
        })
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@case_bp.route('', methods=['GET'])
def list_cases():
    """Listar todos los casos"""
    try:
        case_repo = CaseRepository()
        cases = case_repo.list_all()
        
        return jsonify({
            'cases': [{
                'id': c.id,
                'case_number': c.case_number,
                'title': c.title,
                'status': c.status,
                'severity': c.severity_global,
                'created_at': c.created_at.isoformat() if c.created_at else None
            } for c in cases]
        })
    except Exception as e:
        logger.error(f"Error listing cases: {str(e)}")
        return jsonify({'error': str(e)}), 500


@case_bp.route('/<int:case_id>', methods=['GET'])
def get_case(case_id):
    """Obtener detalles de un caso"""
    try:
        case_repo = CaseRepository()
        ioc_repo = IOCRepository()
        
        case = case_repo.get_by_id(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        iocs = ioc_repo.get_by_case(case_id)
        
        return jsonify({
            'case': {
                'id': case.id,
                'case_number': case.case_number,
                'title': case.title,
                'description': case.description,
                'status': case.status,
                'severity': case.severity_global,
                'created_at': case.created_at.isoformat() if case.created_at else None
            },
            'iocs': [{
                'id': i.id,
                'value': i.value,
                'type': i.type,
                'direction': i.direction
            } for i in iocs]
        })
    except Exception as e:
        logger.error(f"Error getting case {case_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Versión protegida de las rutas para server mode
if APP_MODE == 'server':
    # Override de rutas con autenticación
    @case_bp.route('/protected-example', methods=['GET'])
    @login_required
    def protected_example():
        return jsonify({'message': 'This is a protected endpoint', 'user': g.user.username})
    
    @case_bp.route('/admin-only', methods=['GET'])
    @role_required('admin')
    def admin_only():
        return jsonify({'message': 'Admin only endpoint'})


# Versión original de create_case adaptada para ambos modos
@case_bp.route('', methods=['POST'])
def create_case():
    """Crear un nuevo caso con IOCs"""
    try:
        data = request.get_json()
        
        # Validar IP destino requerida
        if not data.get('destination_ips') or len(data['destination_ips']) == 0:
            return jsonify({'error': 'Se requiere al menos una IP destino'}), 400
        
        # Crear request DTO
        request_dto = CreateCaseRequest(
            title=data['title'],
            description=data.get('description', ''),
            corrective_action=data.get('corrective_action', ''),
            source_ip=data['source_ip'],
            destination_ips=data['destination_ips'],
            hostname=data.get('hostname', '---'),
            os=data.get('os', ''),
            mac=data.get('mac', '---'),
            user=data.get('user', '---'),
            firewall=data.get('firewall', ''),
            antimalware=data.get('antimalware', ''),
            unit=data.get('unit', ''),
            enable_contact=data.get('enable_contact', False),
            responsible_name=data.get('responsible_name', ''),
            email=data.get('email', ''),
            phone_mobile=data.get('phone_mobile', '---'),
            phone_internal=data.get('phone_internal', ''),
            communication_details=data.get('communication_details', ''),
            contacted=data.get('contacted', False),
            conclusion=data.get('conclusion', '')
        )
        
        # Ejecutar caso de uso
        case_repo = CaseRepository()
        create_use_case = CreateCaseUseCase(case_repo)
        
        response = create_use_case.execute(request_dto)
        
        # Analizar IOCs
        ioc_repo = IOCRepository()
        analyze_use_case = AnalyzeIOCsUseCase(ioc_repo)
        analysis_results = analyze_use_case.execute(response.case.id)
        
        # Commit final
        commit_transaction()
        
        return jsonify({
            'case_id': response.case.id,
            'case_number': response.case.case_number,
            'analysis': [r.to_dict() for r in analysis_results]
        }), 201
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating case: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500


@case_bp.route('/<int:case_id>/close', methods=['POST'])
def close_case(case_id):
    """Cerrar un caso"""
    try:
        data = request.get_json()
        if not data.get('conclusion'):
            return jsonify({'error': 'Se requiere conclusión para cerrar el caso'}), 400
        
        case_repo = CaseRepository()
        close_use_case = CloseCaseUseCase(case_repo)
        
        case = close_use_case.execute(case_id, data['conclusion'])
        
        return jsonify({
            'message': 'Case closed',
            'case_id': case.id,
            'case_number': case.case_number
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error closing case: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500


@case_bp.route('/<int:case_id>/export', methods=['GET'])
def export_case(case_id):
    """Exportar caso a Markdown"""
    try:
        case_repo = CaseRepository()
        ioc_repo = IOCRepository()
        export_use_case = ExportCaseUseCase(case_repo, ioc_repo)
        
        filepath = export_use_case.execute(case_id)
        
        return jsonify({
            'file': filepath,
            'message': 'Case exported successfully'
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error exporting case: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500


@case_bp.route('/<int:case_id>/analyze', methods=['POST'])
def analyze_case(case_id):
    """Re-analizar IOCs de un caso"""
    try:
        ioc_repo = IOCRepository()
        analyze_use_case = AnalyzeIOCsUseCase(ioc_repo)
        
        results = analyze_use_case.execute(case_id)
        
        return jsonify({
            'case_id': case_id,
            'analysis': [r.to_dict() for r in results]
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error analyzing case: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500


# Ruta principal (sin cambios)
@case_bp.route('/', methods=['GET'])
def index():
    """Página principal"""
    mode = APP_MODE
    return render_template_string(INDEX_TEMPLATE, mode=mode)