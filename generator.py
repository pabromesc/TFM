#!/usr/bin/python3.6
import sys

# Conversor de archivos en formato "raw.uri" a formato URI simple, eliminando la primera columna,
# correspondiente a la longitud (número de caracteres de la URI).

if __name__ == '__main__':
    
    if len(sys.argv) != 3:
        print('Formato requerido: generator.py file-raw.uri file-out.uri')
        print('file-raw.uri: ruta al fichero de entrada con formato "raw.uri": [Numero_caracteres] [URI].')
        print('file-out.uri: ruta donde se genera el fichero de salida, con formato "file.uri": [URI].')
        sys.exit(1)

    try:
        with open(sys.argv[1], 'r') as raw_file:
            with open(sys.argv[2], 'w') as out_file:
                for line in raw_file:
                    split_line = line.split('/', 1)
                    if len(split_line) == 2:
                        uri = '/' + split_line[1]
                        out_file.write(uri)
    
    except IOError as error:
        print('Error al intentar acceder al archivo {}'.format(error.filename))
        sys.exit(1)