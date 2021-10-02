                                                        Zeek
                                                  Pablo Romero Escot
                                                   README - Spanish
                                                      01-10-2021
------------------------------------------------------------------------------------------------------------------------------------------

FUNCIONAMIENTO

Se trata de una aplicación desarrollada en lenguaje Python la cual se encarga de analizar de forma automática la capacidad
de detección de ataques web basados en URIs HTTP de Zeek. Para ello, primero se desplegará y configurará Zeek para
que monitorice el tráfico entrante en una determinada red, donde se encontrará desplegado un servidor web,
el cual será el destino de todas las peticiones HTTP lanzadas por esta herramienta. Una vez la herramienta ha ejecutado 
todo el tráfico, los logs generados por Zeek serán recogidos y procesados por la aplicación, para que posteriormente 
sean analizados y se extraigan las URIs que han sido detectadas como ataque.

Para ello, la herramienta consta de 5 scripts. Para cada uno se indica:

a) Descripción
b) E/S: Entrada -> Salida
c) Sintaxis (de llamada)

Posteriormente se describen en mayor detalle los formatos de los distintos tipos de ficheros empleados.

#########
1) complete.py

a) Descripción: Se trata del script principal de la herramienta. Su función es ejecutar automáticamente 
   el proceso completo de la aplicación, encargándose de ejecutar el resto de scripts cuando sea necesario
   llevar a cabo la función que cada uno de ellos tiene asignada.

b) E/S: file-raw.uri -> Como salida genera los diferentes archivos que cada uno de los scripts
   que ejecuta se encarga de realizar

c) Sintaxis:
   complete.py  file-raw.uri  file.uri  dir_out_time  dir_out_log  dir_out_attacks  dir_out_clean

   * "file-raw.uri": ruta del fichero de entrada con formato "raw.uri".
   * "file.uri": ruta al fichero que se va a generar con la lista de URIs que se desean analizar.
   * "dir_out_time": ruta al directorio donde se va a generar el archivo "file.time".
   * "dir_out_log": ruta al directorio donde se va a almacenar el archivo con los logs generados por Zeek, despues de que hayan sido procesados.
   * "dir_out_attacks": ruta al directorio donde se va a generar el archivo con la lista de URIs identificadas como ataques.
   * "dir_out_clean": ruta al directorio donde se va a generar el archivo con la lista de URIs NO identificadas como ataques.
   * "numerical_results_file": ruta al fichero el cual se va a crear o modificar con los resultados numéricos del análisis.
#########

#########
2) generator.py

a) Descripción: Se encarga de procesar el dataset original proporcionado ("X-raw.uri"), donde cada 
   línea está compuesta por una URI y el número de caracteres que tiene dicha URI, y de generar un
   nuevo fichero donde cada línea está formada únicamente por una URI.

b) E/S: file-raw.uri -> file.uri

c) Sintaxis:
   generator.py   file-raw.uri   file-out.uri

   * "file-raw.uri": ruta al fichero de entrada con formato "raw.uri": {Numero_caracteres} {URI}.
   * "file-out.uri": ruta donde se genera el fichero de salida, con formato "file.uri": {URI}.
#########

#########
3) launcher.py

a) Descrición: Se encarga de leer el fichero que se le proporciona como entrada, "file.uri", y 
   de ejecutar las diferentes URIs que componen dicho fichero contra un servidor web, generando 
   un fichero "file.time" como registro de las URIs ejecutadas y el instante en el que se 
   han llevado a cabo.

b) E/S: file.uri -> file.time

c) Sintaxis:
   launcher.py   file.uri   dir_out_time

   * "file.uri": ruta al fichero con la lista de URIs que se desean analizar, con formato: {URI}.
   * "dir_out_time": ruta al directorio donde se va a generar el archivo "file.time", con formato: {Timestamp}\t{URI}.
#########

#########
4) analyzer.py

a) Descripción: Tiene como objetivo principal la obtención de los logs que genera Zeek, extraer de estos 
   aquella información que nos es útil y procesarla. Los resultados se almacenan en dos ficheros, en uno
   se incluyen únicamente las URIs detectadas como ataques, el instante de tiempo en el que se produjeron
   y regla que la detectó (file.log), y en el otro fichero se almacena esta información junto con más 
   detalles que aporta Zeek con respecto a la alerta, como que tipo de alerta se ha producido o una 
   pequeña descripción de lo ocurrido (file_detailed.log).

b) E/S: http.log, notice.log, signatures.log -> file.log, file_detailed.log

c) Sintaxis:
   analyzer.py   dir_out_log   id_log_file

   * "dir_out_log": ruta al directorio donde se va a almacenar el archivo con los logs generados por Zeek,
      después de que hayan sido procesados.
   * "id_log_file": nombre identificatorio que se le va a asignar al archivo generado con los logs
      una vez procesados.

   NOTA: Los ficheros de LOGs se obtienen de su ubicación estándar:
   * Carpeta: /usr/local/zeek/logs/current/
   * Nombre:  
      * http.log
      * notice.log
      * signatures.log
#########

#########
5) detector.py

a) Descrición: Obtiene aquellas URIs que han sido detectadas como ataques por Zeek, así como cuales han sido catalogadas como 
   tráfico limpio. 

b) E/S: file-raw.uri, file.time, file.log -> file.attacks, file.attacks-extendido, file.clean, numerical-results-file.txt

c) Sintaxis:
   detector.py  file-raw.uri  file.time  file.log  dir_out_attacks  dir_out_clean  numerical-result-file.txt
        
   * "file-raw.uri": ruta al fichero de entrada con formato "raw.uri".
   * "file.time": fichero con la lista de URIs ejecutadas y el instante de tiempo en el que fueron lanzadas cada una de ellas.
   * "file.log": fichero con los logs generados por Zeek, los cuales han sido previamente procesados.
   * "dir_out_attacks": ruta al directorio donde se va a generar el archivo con la lista de URIs 
      identificadas como ataques.
   * "dir_out_clean": ruta al directorio donde se va a generar el archivo con la lista de URIs NO identificadas
      como ataques.
   * "numerical-results-file.txt": ruta al fichero el cual se va a crear o modificar con los resultados 
      numéricos del analisis.
#########


############################
FORMATO DE FICHEROS EMPLEADOS

1) "file-raw.uri": fichero con las URIs a analizar y el número de caracteres de cada una. Formato:

   {Nº_caracteres_URI} {URI}

2) "file.uri": fichero con únicamente las URIs a analizar. Formato:

   {URI}

3) "file.time": fichero con las URIs enviadas al servidor web y el TimeStamp en el cual se han enviado. Formato:

   {TimeStamp}\t{URI}

4) "file.log":	fichero con los resultados de obtener los logs generados por Zeek y realizar el procesamiento
   de dicha información, conservando únicamente los campos referentes al TimeStamp en el que se produjo la alerta,
   la URI y el identificador de la regla que la detectó. Formato:

   {TimeStamp}\t{URI}\t{ID_regla}

5) "file_detailed.log": fichero con los resultados de obtener los logs generados por Zeek y realizar el procesamiento
   de dicha información, incluyendo más detalles de la detección en un formato más legible. Si no se ha detectado 
   ninguna URI como un ataque, este archivo no se crea. Formato:

   URI: {URI}
   Type: {tipo de alerta}
   Message: {pequeña descripción de lo ocurrido}
   Signature identifier: {identificador de la regla que ha desencadenado la alerta}
   Timestamp: {instante de tiempo en el que se produjo}

6) "file.attacks": conjunto de URIs catalogadas como tráfico malicioso. Formato:

   {URI}

7) "file.attacks-extendido": fichero con la lista de URIs detectadas como ataques, junto con el número de la 
   línea en la que se encuentra dicha URI dentro del dataset proporcionado, el número de reglas que se han 
   activado debido a su ejecución y el identificador de cada una de estas reglas. Formato: 

   Packet [{}]\tUri [{}]\t Nattacks [{}]\t[{ID_regla_1}]\t[{ID_regla_2}]…

8) "file.clean": conjunto de URIs catalogadas como tráfico limpio. Formato:

   {URI}

9) "numerical-results-file.txt": resultados numéricos obtenidos con el análisis. Se registran el número 
   de peticiones ejecutadas, número de aquellas que han sido consideradas como ataques y número de
   peticiones que han sido catalogadas como tráfico limpio. Formato:

   {Nombre del fichero analizado}:
   Numero de URIs procesadas: {}
   Numero de URIs detectadas como ataque: {}
   Numero de URIs NO detectadas como ataque: {}