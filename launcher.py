#!/usr/bin/python3.6
import sys
import requests
import time
from datetime import datetime

# Se encarga de leer el fichero que se le proporciona como entrada, "fichero.uri", 
# y ejecutar las diferentes URIs que componen dicho fichero contra un servidor web,
# generando un fichero "fichero.time" con la sintaxis: [Timestamp]\t[URI], como registro de las URIs
# ejecutadas y el instante en el que se han llevado a cabo.

if __name__ == '__main__':
    
    if len(sys.argv) != 3:
        print('Formato requerido: launcher.py file.uri dir_out_time')
        print('file.uri: Ruta al fichero con la lista de URIs que se desean analizar, con formato: [URI].')
        print('dir_out_time: ruta al directorio donde se va a generar el archivo "fichero.time", con formato: [Timestamp]\t[URI].')
        sys.exit(1)


    # Importante no poner "/" al final de la dirección del servidor para no provocar una doble "//" al añadir las URIs
    SERVER_URL = "http://192.168.65.136:8080"

    input_line_number = 0
    input_total_line_number = 0

    # Se obtiene el nombre del fichero con la lista de URIs
    if (sys.argv[1].find('/') != -1):
        uri_file_name = sys.argv[1][sys.argv[1].rfind('/') + 1:]
    else:
        uri_file_name = sys.argv[1]

    # El fichero ".time" va a tener el mismo nombre que el fichero de entrada, modificándose su extensión 
    time_file_name = uri_file_name[:uri_file_name.rfind('.')] + ".time"
    time_file_path = sys.argv[2] + "/" + time_file_name

    error_uri = 0

    try:
        # Se realiza un recuento de las URIs que contiene el fichero ".uri"
        with open(sys.argv[1], 'r') as uri_file: 
            for line in uri_file:
                if line != "\n":
                    input_total_line_number += 1

        with open(sys.argv[1], 'r') as uri_file:
            with open(time_file_path, 'w') as time_file:
                for uri in uri_file:
                    input_line_number += 1
                    print('Uri {} de {}'.format(input_line_number, input_total_line_number))
                    URL = SERVER_URL + uri.rstrip('\n')
                    timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M')
                    time_file.write('{}\t{}'.format(timestamp, uri))
                    
                    try:
                        req = requests.get(URL, verify=False, timeout=2)
                    except:
                        error_uri += 1
                        print("Error al intentar ejecutar una peticion GET a la URL: {}".format(URL))

    except IOError as error:
        print('Error al intentar acceder al archivo {}'.format(error.filename))
        sys.exit(1)
    
    if (error_uri > 0):
        print("Se han producido errores en el intento de ejecucion de {} URIs.".format(error_uri))

    # Se añade una pausa de un segundo para que cuando se realice todo el proceso automatizado, 
    # Zeek tenga tiempo de registrar todos los logs antes de que se ejecute el siguiente script
    time.sleep(2)