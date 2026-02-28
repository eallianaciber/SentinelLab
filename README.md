SentinelLab

Aplicación web para la gestión estructurada de informes de investigación de eventos de ciberseguridad.

SentinelLab permite documentar, analizar y almacenar reportes técnicos de incidentes, incluyendo análisis de IoC, IPs, artefactos, evidencia técnica y conclusiones operativas.

🚀 Stack Tecnológico

Python 3.11+

Flask (Application Factory Pattern)

SQLAlchemy ORM

SQLite (entorno local)

Preparado para PostgreSQL (entorno servidor)

Jinja2

HTML/CSS (Frontend básico)

🧠 Arquitectura

El proyecto utiliza el patrón Application Factory, lo que permite:

Separación clara de configuración

Soporte para múltiples entornos

Mejor testabilidad

Escalabilidad modular

Estructura general:

SentinelLab/
│
├── app/
│   ├── factory.py
│   ├── models/
│   ├── services/
│   ├── routes/
│   ├── templates/
│   └── static/
│
├── requirements.txt
├── run.py
└── README.md
⚙️ Instalación
1️⃣ Clonar repositorio
git clone https://github.com/eallianaciber/SentinelLab.git
cd SentinelLab
2️⃣ Crear entorno virtual

Windows:

python -m venv venv
venv\Scripts\activate

Linux/macOS:

python3 -m venv venv
source venv/bin/activate
3️⃣ Instalar dependencias
pip install -r requirements.txt
▶️ Ejecutar en modo desarrollo
python run.py

Por defecto correrá en:

http://127.0.0.1:5000
🔐 Variables de Entorno (Recomendado)

Para entorno productivo, configurar:

Linux/macOS:

export FLASK_ENV=production
export SECRET_KEY="clave_segura"

Windows:

set FLASK_ENV=production
set SECRET_KEY=clave_segura
🗄 Base de Datos
Modo desarrollo

SQLite local

Preparado para producción

PostgreSQL (configurable vía URI)

Ejemplo:

postgresql://usuario:password@localhost:5432/sentinellab
📊 Funcionalidades Principales

Registro de casos de investigación

Gestión de IPs y artefactos

Análisis de IoC

Clasificación de severidad

Registro estructurado de evidencia

Generación de informes técnicos

Base de datos persistente

🔎 Buenas Prácticas Implementadas

Application Factory Pattern

Separación por capas (modelos, servicios, rutas)

Preparado para múltiples entornos

Escalable a arquitectura modular

ORM para evitar SQL injection

🚧 Pendientes / Mejoras Futuras

Implementación de autenticación y control de acceso

Tests automatizados con pytest

Integración de migraciones con Flask-Migrate

Exportación automática de informes en PDF

Dockerización

Logging estructurado

🛡 Seguridad

Recomendaciones para producción:

No usar debug=True

Configurar SECRET_KEY

Usar servidor WSGI (Gunicorn)

Habilitar HTTPS

No subir base de datos SQLite a repositorio

Usar variables de entorno para credenciales

📌 Modo Producción (Ejemplo con Gunicorn)
pip install gunicorn
gunicorn -w 4 run:app
👨‍💻 Autor

Alejandro Alliana
Proyecto enfocado en investigación técnica y análisis estructurado de eventos de ciberseguridad.
