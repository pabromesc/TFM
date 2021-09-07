#!/usr/bin/python3.6
import sys
import urllib.parse

# Recibe como entrada los ficheros "fichero.time" y "fichero.log" y los compara 
# a fin de obtener por un lado aquellas URIs que Zeek ha considerado como ataques (fichero.attacks)
# y por otro lado aquellas URIs que Zeek NO ha considerado como ataques (fichero.clean)

if __name__ == '__main__':
    
    if len(sys.argv) != 7:
        print('Formato requerido: detector.py file-raw.uri file.time file.log dir_out_attacks dir_out_clean numerical-result-file.txt')
        print('file-raw.uri: ruta al fichero de entrada con formato "raw.uri": [Numero_caracteres] [URI].')
        print('file.time: fichero con la lista de URIs ejecutadas y el instante de tiempo en el que fueron lanzadas cada una de ellas.')
        print('file.log: fichero con los logs generados por Zeek, los cuales han sido previamente procesados.')
        print('dir_out_attacks: ruta al directorio donde se va a generar el archivo con la lista de URIs identificadas como ataques.')
        print('dir_out_clean: ruta al directorio donde se va a generar el archivo con la lista de URIs NO identificadas como ataques.')
        print('numerical-results-file.txt: ruta al fichero el cual se va a crear o modificar con los resultados numericos del analisis.')
        sys.exit(1)

    total_uri_number = 0
    clean_uri_number = 0
    attack_uri_number = 0

    raw_file_path = sys.argv[1]
    time_file_path = sys.argv[2]
    log_file_path = sys.argv[3]

    # Se obtiene el nombre asignado al fichero con los logs para asignar el mismo nombre identificatorio al archivo con
    # la lista de URIs identificadas como ataques (.attacks), al archivo con la lista de URIs NO identificadas como ataques (.clean)
    # y al archivo con los detalles de los ataques detectados (.attacks-extendido).
    if (log_file_path.find('/') != -1):
        log_file_name = log_file_path[log_file_path.rfind('/') + 1:log_file_path.rfind('.')]
    else:
        log_file_name = log_file_path[:log_file_path.rfind('.')]

    attack_uri_file_path = sys.argv[4] + "/" + log_file_name + ".attacks"
    extended_attack_file_path = sys.argv[4] + "/" + log_file_name + ".attacks-extendido"
    clean_uri_file_path = sys.argv[5] + "/" + log_file_name + ".clean"
    
    try:
        attack_uri_file = open(attack_uri_file_path, 'w')
        extended_attack_file = open(extended_attack_file_path, 'w')
        clean_uri_file = open(clean_uri_file_path, 'w')

        with open(time_file_path, 'r') as time_file:             
            for time_uri_line in time_file:
                total_uri_number += 1
                split_time_uri_line = time_uri_line.split('\t') 
                
                if (len(split_time_uri_line) == 2):
                    ts_time_file = split_time_uri_line[0]
                    uri_time_file = split_time_uri_line[1]

                    # Convertimos las URIs a un formato común que nos permita establecer similitudes 
                    # entre las URIs proporcionadas y las registradas como ataques por Zeek
                    processed_uri_time_file = urllib.parse.unquote(urllib.parse.unquote(uri_time_file).strip())
                    
                    Nattacks = 0
                    id_signature = ""

                    with open(log_file_path, 'r') as log_file:
                        for log_line in log_file:
                            split_log_line = log_line.split('\t')
                            
                            if (len(split_log_line) == 3):
                                ts_log_file = split_log_line[0]
                                uri_log_file = split_log_line[1]

                                if (ts_time_file == ts_log_file and processed_uri_time_file.find(urllib.parse.unquote(uri_log_file)) != -1):
                                    Nattacks += 1  
                                    if (Nattacks == 1):
                                        id_signature = "[" + split_log_line[2].strip() + "]"
                                    else:
                                        id_signature += "\t[" + split_log_line[2].strip() + "]"

                        if Nattacks == 0:
                            clean_uri_number += 1
                            clean_uri_file.write(uri_time_file)
                        
                        else:
                            attack_uri_number += 1
                            attack_uri_file.write(uri_time_file) 

                            line_number = 0
                            with open(raw_file_path, 'r') as raw_file:
                                for raw_uri_line in raw_file:
                                    line_number += 1
                                    split_raw_uri_line = raw_uri_line.split('/', 1)
                                    if len(split_raw_uri_line) == 2:
                                        uri = '/' + split_raw_uri_line[1]
                                        if (uri == uri_time_file):
                                            break
                            
                            extended_attack_file.write("Packet [{}]\tUri [{}]\t Nattacks [{}]\t{}\n".format(line_number, uri_time_file.strip(), Nattacks, id_signature))

        attack_uri_file.close()
        extended_attack_file.close()
        clean_uri_file.close()

        print('Numero de URIs procesadas: {}'.format(total_uri_number))
        print('Numero de URIs detectadas como ataque: {}'.format(attack_uri_number))
        print('Numero de URIs NO detectadas como ataque: {}'.format(clean_uri_number))
        
        with open(sys.argv[6], 'a+') as numerical_results_file:
            numerical_results_file.write('{}:\n'.format(log_file_name))
            numerical_results_file.write('Numero de URIs procesadas: {}\n'.format(total_uri_number))
            numerical_results_file.write('Numero de URIs detectadas como ataque: {}\n'.format(attack_uri_number))
            numerical_results_file.write('Numero de URIs NO detectadas como ataque: {}\n\n'.format(clean_uri_number))

    except IOError as error:
        print('Error al intentar acceder al archivo {}'.format(error.filename))
        sys.exit(1)