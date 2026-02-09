# SQL ARES [LZL] - Suite de Inyección SQL Avanzada

**ARES [LZL]** es una herramienta de pruebas de seguridad y explotación de inyecciones SQL diseñada para entornos modernos. Construida con una interfaz gráfica potente basada en Streamlit, permite a los investigadores de seguridad y pentesters detectar, analizar y extraer información de bases de datos vulnerables de manera eficiente.

## 🚀 Características Principales

*   **Interfaz Gráfica Moderna (Cyber Minimalist):** Panel de control intuitivo con tema oscuro y acentos neón.
*   **Motor "Búho Racional":** Sistema de detección inteligente que identifica automáticamente vectores de ataque (Error-Based y Union-Based).
*   **Detección Automática de WAF/Evasión:** Soporte para scripts de "tamper" (bypass de filtros) y rotación de User-Agents.
*   **Extracción Masiva (Access Deep):**
    *   **Union-Based:** Extracción de alta velocidad utilizando inyecciones UNION.
    *   **Error-Based:** Extracción fiable mediante errores XPATH.
    *   **Smart Batching:** Algoritmo adaptativo que optimiza el tamaño de los lotes de extracción para evitar bloqueos y truncamientos.
    *   **Particionamiento Vertical:** Manejo automático de tablas con gran cantidad de columnas.
*   **Gestión de Sesiones:** Guarda y carga configuraciones de objetivos y estados de explotación.
*   **Soporte Multi-Base de Datos:** Enfocado principalmente en MySQL/MariaDB, con capacidad de adaptación.

## 🛠️ Instalación

1.  **Requisitos Previos:**
    *   Python 3.10+
    *   Pip

2.  **Instalar Dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Uso

Ejecuta la interfaz gráfica con el siguiente comando:

```bash
streamlit run gui_exploit.py
```
o
```bash
python -m streamlit run gui_exploit.py
```

### Flujo de Trabajo

1.  **API EXPLOIT:** Configura el objetivo (URL, método, datos POST, cookies).
2.  **INSPECCIÓN:** Lanza el escáner "Búho Racional" para detectar vulnerabilidades. El sistema identificará automáticamente si es posible realizar ataques Union-Based o Error-Based.
3.  **ACCESS DEEP:** Una vez confirmada la vulnerabilidad, navega por las bases de datos, tablas y columnas. Extrae datos masivos y exportalos a CSV.

## ⚠️ Aviso Legal

Esta herramienta ha sido creada únicamente con fines educativos y para pruebas de seguridad autorizadas. El uso de **SQL ARES [LZL]** contra sistemas sin el consentimiento explícito de sus propietarios es ilegal. Los desarrolladores no se hacen responsables del mal uso de este software.

---
*Desarrollado por AlexisLzL - 2026*
