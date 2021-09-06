#!/usr/bin/python3.6
import sys
import os
from datetime import datetime

# Obtiene los logs generados por Zeek con respecto al trafico http cursado y con
# respecto a las alertas generadas. A partir de estos ficheros, realiza un procesamiento para
# generar un solo fichero con toda la informacion relevante para el analisis.

if __name__ == '__main__':
    
    if len(sys.argv) != 3:
        print('Formato requerido: analyzer.py dir_out_log id_log_file')
        print('dir_out_log: ruta al directorio donde se va a almacenar el archivo con los logs generados por Zeek, despues de que hayan sido procesados ("fichero.log").')
        print('id_log_file: nombre identificatorio que se le va a asignar al archivo generado con los logs una vez procesados.')
        sys.exit(1)

    # Metodo mediante el que han sido ejecutadas las URIs
    METHOD = "GET"
    
    # Caracter con el cual Zeek identifica un campo vacio
    EMPTY_FIELD = "-"

    # Contenido extra que añade Zeek en los logs correspondientes a la URI ejecutada, registrados en el archivo notice.log,
    # cuando se ejecutan ciertos tipos de ataques. 
    UNWANTED_ADDED_CONTENT = "HTTP/1.1\\x0d\\x0a"

    # Ubicacion de los diferentes archivos de logs que genera Zeek
    NOTICE_LOG_PATH = "/usr/local/zeek/logs/current/notice.log"
    HTTP_LOG_PATH = "/usr/local/zeek/logs/current/http.log"
    SIGNATURES_LOG_PATH = "/usr/local/zeek/logs/current/signatures.log"

    timestamp =  datetime.now().strftime('%Y-%m-%d')
    id_log_file = sys.argv[2]
    log_file_path = sys.argv[1] + "/" + id_log_file + "_" + timestamp + ".log"
    detailed_log_file_path = sys.argv[1] + "/" + id_log_file + "_" + timestamp + "_detailed"+ ".log"
    
    if os.path.isfile(NOTICE_LOG_PATH) and os.path.isfile(HTTP_LOG_PATH):
        processed_notice_log_path = "/tmp/notice_" + id_log_file + "_" + timestamp + ".log"
        processed_http_log_path = "/tmp/http_" + id_log_file + "_" + timestamp + ".log"
        processed_signatures_log_path = "/tmp/signatures_" + id_log_file + "_" + timestamp + ".log"

        try: 
            # Se obtiene de cada archivo de logs las columnas de datos que nos interesan, haciendo uso de la herramienta zeek-cut
            os.system('cat {} | zeek-cut ts uri tags > {}'.format(HTTP_LOG_PATH, processed_http_log_path))
            os.system('cat {} | zeek-cut ts sub note msg > {}'.format(NOTICE_LOG_PATH, processed_notice_log_path))

            if os.path.isfile(SIGNATURES_LOG_PATH):
                os.system('cat {} | zeek-cut ts sub_msg sig_id > {}'.format(SIGNATURES_LOG_PATH, processed_signatures_log_path))

            else:
                open(processed_signatures_log_path, "w").close()

            total_number_line_log = 0
            
            try:
                log_file = open(log_file_path, 'w')
                detailed_log_file = open(detailed_log_file_path, 'w')
                
                with open(processed_notice_log_path, 'r') as processed_notice_log: 
                    for notice_line in processed_notice_log:
                        total_number_line_log += 1
                        
                        split_notice_line = notice_line.split('\t')                         
                        ts_epoch_format = split_notice_line[0]
                        uri = split_notice_line[1]

                        with open(processed_signatures_log_path, 'r') as processed_signatures_log:
                            signature_id = "script"
                            for signature_line in processed_signatures_log:
                                split_signature_line = signature_line.split('\t')
                                if (ts_epoch_format == split_signature_line [0] and uri == split_signature_line[1]):
                                    signature_id = split_signature_line[2].strip()
                                    break

                        # A continuacion se realiza un procesamiento para registrar las URIs en un formato 
                        # que permita poder establecer igualdades mas facilmente en detector.py

                        # Si en el campo destinado a la URI se registra la URI junto con el metodo con el cual se ejecuto, 
                        # se elimina del registro dicho metodo, registrando solo la URI
                        if (uri.startswith(METHOD)):
                            uri = uri[len(METHOD)+1:]
                        
                        # En el caso de que la alerta que se ejecuta cuando se detecta un ataque no registre la URI 
                        # en el fichero notice.log, obtenemos la URI utilizando el fichero http.log
                        if (uri == EMPTY_FIELD):
                            with open(processed_http_log_path, 'r') as processed_http_log:
                                for http_line in processed_http_log:
                                    split_http_line = http_line.split('\t')
                                    http_ts = split_http_line[0]
                                    if (ts_epoch_format == http_ts):
                                        uri = split_http_line[1]
                                        signature_id += '-{}'.format(split_http_line[2].strip()) 
                                        break
                        
                        # Si se añade un contenido extra al registro de la URI, este contenido indeseado se elimina
                        if (uri.find(UNWANTED_ADDED_CONTENT) != -1):
                            uri = uri[:uri.find(UNWANTED_ADDED_CONTENT)-1]

                        uri = uri.replace('\\x', '%') 
                        
                        # Se modifica el formato del timestamp a un formato mas legible
                        ts = datetime.fromtimestamp(float(ts_epoch_format)).strftime('%Y-%m-%dT%H:%M')
                        
                        log_file.write('{}\t{}\t{}\n'.format(ts, uri, signature_id))
                        detailed_log_file.write('URI: {}\n'.format(uri))
                        detailed_log_file.write('Type: {}\n'.format(split_notice_line[2]))
                        detailed_log_file.write('Message: {}\n'.format(split_notice_line[3].strip()))
                        detailed_log_file.write('Signature identifier: {}\n'.format(signature_id))
                        detailed_log_file.write('Timestamp: {}\n\n'.format(ts))

                log_file.close()
                detailed_log_file.close()
                print('Total de alertas procesadas: {}'.format(total_number_line_log))

            except IOError as error:
                print('Error al intentar acceder al archivo {}'.format(error.filename))
                sys.exit(1)

        except Exception as error:
            print('Error: {}'.format(error))
            sys.exit(1)
    
    else:
        print('Ningun intento de ataque detectado')

        # El fichero de logs debe generarse aunque no haya ataques, de forma que el siguiente script
        # en el procedimiento, detector.py, pueda ejecutarse correctamente.
        open(log_file_path, 'w').close()