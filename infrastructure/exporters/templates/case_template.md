{# infrastructure/exporters/templates/case_template.md.j2 #}
# Informe de Caso SOC: {{ case.case_number }}

## 1. Información General

| Campo | Valor |
|-------|-------|
| **Número de Caso** | {{ case.case_number }} |
| **Título** | {{ case.title }} |
| **Estado** | {{ case.status | upper }} |
| **Severidad Global** | {{ case.severity_global }}/100 |
| **Fecha de Creación** | {{ case.created_at.strftime('%Y-%m-%d %H:%M:%S') }} |
| **Última Actualización** | {{ case.updated_at.strftime('%Y-%m-%d %H:%M:%S') if case.updated_at else 'N/A' }} |

## 2. Descripción del Incidente

{{ case.description or 'Sin descripción proporcionada' }}

## 3. Datos del Equipo Afectado

{% if asset %}
| Campo | Valor |
|-------|-------|
| **Unidad/Área** | {{ asset.unit or 'No especificada' }} |
| **Hostname** | {{ asset.hostname }} |
| **Sistema Operativo** | {{ asset.os or 'No especificado' }} |
| **IP Origen** | {{ asset.source_ip }} |
| **Dirección MAC** | {{ asset.mac }} |
| **Usuario** | {{ asset.user }} |
| **Firewall** | {{ asset.firewall or 'No especificado' }} |
| **Antimalware** | {{ asset.antimalware or 'No especificado' }} |
{% else %}
*No se registraron datos del equipo afectado*
{% endif %}

## 4. IPs Analizadas

### IPs Destino

{% for ioc in destination_iocs %}
#### {{ ioc.value }}
{% if ioc.analyses %}
- **Score Final**: {{ ioc.analyses.final_score }}/100
- **Clasificación**: {{ ioc.analyses.classification | upper }}
- **Detalles por Fuente**:
  {% if ioc.analyses.vt_score > 0 %}  - VirusTotal: {{ ioc.analyses.vt_score }}/100{% endif %}
  {% if ioc.analyses.abuse_score > 0 %}  - AbuseIPDB: {{ ioc.analyses.abuse_score }}/100{% endif %}
  {% if ioc.analyses.greynoise_score > 0 %}  - GreyNoise: {{ ioc.analyses.greynoise_score }}/100{% endif %}
  {% if ioc.analyses.ibm_score > 0 %}  - IBM X-Force: {{ ioc.analyses.ibm_score }}/100{% endif %}
{% else %}
*Pendiente de análisis*
{% endif %}
{% else %}
*No se registraron IPs destino*
{% endfor %}

### IP Origen
{% if source_ioc %}
- **{{ source_ioc.value }}** (Interna: {{ 'Sí' if source_ioc.is_internal else 'No' }})
{% else %}
*No se registró IP origen*
{% endif %}

## 5. Resumen Técnico de IOC

| IP | Tipo | Score | Clasificación | Fuentes |
|-----|------|-------|---------------|---------|
{% for ioc in destination_iocs %}
| {{ ioc.value }} | {{ ioc.type | upper }} | {{ ioc.analyses.final_score if ioc.analyses else 'N/A' }} | {{ ioc.analyses.classification if ioc.analyses else 'Pendiente' }} | {% if ioc.analyses %}{{ ioc.analyses.sources_contributing | join(', ') if ioc.analyses.sources_contributing else 'Ninguna' }}{% else %}N/A{% endif %} |
{% endfor %}

## 6. Acción Correctiva

{{ case.corrective_action or 'No se especificó acción correctiva' }}

## 7. Contacto

{% if contact %}
- **Responsable**: {{ contact.responsible_name or 'No especificado' }}
- **Email**: {{ contact.email or 'No especificado' }}
- **Teléfono Móvil**: {{ contact.phone_mobile }}
- **Teléfono Interno**: {{ contact.phone_internal or 'No especificado' }}
- **Fecha de Contacto**: {{ contact.contact_date.strftime('%Y-%m-%d %H:%M:%S') if contact.contact_date else 'N/A' }}
- **Contactado**: {{ 'Sí' if contact.contacted else 'No' }}
- **Detalles de Comunicación**:
  
  {{ contact.communication_details or 'Sin detalles' }}
{% else %}
*No se registró información de contacto*
{% endif %}

## 8. Conclusión

{{ case.conclusion or 'Pendiente de conclusión' }}

---

*Informe generado automáticamente por SOC Case Manager*
*Fecha de generación: {{ generation_date.strftime('%Y-%m-%d %H:%M:%S') }}*