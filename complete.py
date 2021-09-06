#!/usr/bin/python3.6
import sys
import subprocess
from datetime import datetime

if __name__ == '__main__':
    
    if len(sys.argv) != 8:
        print('Formato requerido: complete.py file-raw.uri file.uri dir_out_time dir_out_log dir_out_attacks dir_out_clean')
        print('file-raw.uri: ruta del fichero de entrada con formato "raw.uri": Numero_caracteres   URI.')
        print('file.uri: Ruta al fichero con la lista de URIs que se desean analizar. Formato: URI.')
        print('dir_out_time: ruta al directorio donde se va a generar el archivo "fichero.time", con formato: Timestamp   URI.')
        print('dir_out_log: ruta al directorio donde se va a almacenar el archivo con los logs generados por Zeek, despues de que hayan sido procesados ("fichero.log").')
        print('dir_out_attacks: ruta al directorio donde se va a generar el archivo con la lista de URIs identificadas como ataques.')
        print('dir_out_clean: ruta al directorio donde se va a generar el archivo con la lista de URIs NO identificadas como ataques.')
        print('numerical_results_file: ruta al fichero el cual se va a crear o modificar con los resultados numericos del analisis.')
        sys.exit(1)

    raw_uri_file = sys.argv[1]
    uri_file = sys.argv[2]
    time_folder = sys.argv[3]
    log_folder = sys.argv[4]
    attack_uri_folder = sys.argv[5]
    clean_uri_folder = sys.argv[6]
    numerical_results_file = sys.argv[7]
    
    # Se utiliza el nombre asignado al archivo que contiene la lista de URIs que se van a analizar como 
    # nombre identificatorio para los archivos que se generan posteriormente en analyzer.py y detector.py
    if (uri_file.find('/') != -1):
        id_file = uri_file[uri_file.rfind('/') + 1:uri_file.rfind('.')]
    else:
        id_file = uri_file[:uri_file.rfind('.')]
    
    print("--> Ejecutando generator.py...")
    try:
        subprocess.call(['python3.6', 'generator.py', raw_uri_file, uri_file])
    except:
        print("Error en la ejecucion de generator.py")
        sys.exit(1)

    print("--> Ejecutando launcher.py...")
    try:
        subprocess.call(['python3.6', 'launcher.py', uri_file, time_folder])
    except:
        print("Error en la ejecucion de launcher.py")
        sys.exit(1)

    timestamp =  datetime.now().strftime('%Y-%m-%d')
    time_file_path = time_folder + "/" + id_file + ".time"
    log_file_path = log_folder + "/" + id_file + "_" + timestamp + ".log"
    
    print("--> Ejecutando analyzer.py...")
    try:
        subprocess.call(['python3.6', 'analyzer.py', log_folder, id_file])
    except:
        print("Error en la ejecucion de analyzer.py")
        sys.exit(1)

    print("--> Ejecutando detector.py...")
    try:
        subprocess.call(['python3.6' ,'detector.py', raw_uri_file, time_file_path, log_file_path, attack_uri_folder, clean_uri_folder, numerical_results_file])
    except:
        print("Error en la ejecucion de detector.py")
        sys.exit(1)