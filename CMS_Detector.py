import requests
from json import loads
from concurrent.futures import ThreadPoolExecutor

##############################################
#           TOOL Extraida de mgt0ls          #
#       mi proyecto de ciberseguridad        #   mgt0ls =>> [ OK ]
#                   T00LS                    #
##############################################

def apidetector(url_ = None, deep_ = None):

    results_inf_ = {}
    to_scan = []
    deep_scan = []
    switch_ = False

    # Intentamos abrir el archivo que contiene toda la informacion de los CMS
    try:
        with open("web_control.json", "r", encoding="utf-8") as read_:
            all_json = loads(read_.read())

            self_hosted = all_json[0] # CMS almacenados en el propio servidor
            deep_shosted = all_json[2] # CMS profundo en el propio servidor
            saas = all_json[1] # CMS como servicio externo
    
    except Exception as err:
        print(f"[ERROR] {err}")
        return

    # Si no tiene el formato indicado se retorna
    if "://" not in url_:
        print("[ERROR] La URL no cumple con el formato. Ejemplo: https://example.com/")
        return
    
    # Si trae / de mas, se elimina
    if url_.endswith("/"):
        url_ = url_[:-1]

    # Funcion encargada de verificar si es CMS externo
    def is_saas(html_code):

        cms_detect = ""
        results_temp = []

        # Hacemos el html iterable
        html_code = html_code.replace(">", ">\n").split("\n")
        
        # Por cada linea dentro del codigo html verificamos que exista el CMS correspondiente
        for line in html_code:
            
            # Por cada SaaS se verifica si hay vinculo hacia la api externa
            for key_ in saas.keys():
                
                # Si es asi se agrega a una lista temporal
                if saas[key_] in line:
                    results_temp.append(line)

                    # Si no se detecto un cms externo se le asigna el detectado
                    if not cms_detect:
                        cms_detect = key_

        # Si no se encontraron resultados se termina la ejecucion de esta funcion
        if not results_temp:
            print("[ERROR] No se logro detectar ningun CMS en el codigo =>> [BAD]")
            return
        
        # Si se encontaron se agrega al json final
        print(f"[INFO] CMS detectado en codigo =>> [{cms_detect.upper()}]")
        results_inf_.setdefault(cms_detect, results_temp)

    # Iniciamos la conexion y ejecutamos la funcion
    try:
        sas_query = requests.get(url_, timeout=10)
        is_saas(sas_query.text)

    except KeyboardInterrupt:
        return
    
    except Exception as err:
        print(f"[ERROR] {err}")

    # Esta funcion se encarga de detectar el nombre de la api con el url
    def detect_api(url_):

        final_url = ""
        cms_self = ""

        # Reemplazamos los :// para luego hacerla una lista con split y borramos el dominio de la url
        url_ = url_.replace("://", "").split("/")
        url_.pop(0)

        # Reconstruimos la url iterando sobre ella
        for elem in url_:
            final_url = final_url + "/" + elem

        # Buscamos dentro de cada bloque de los datos de self hosted hasta encontrar el enlace
        for key_ in self_hosted.keys():
            
            # Si el switch esta en True el escaneo retorna el nombre desde deep_shosted y saltamos iteracion
            if switch_:
                if final_url in str(deep_shosted[key_]):
                    cms_self = key_
                continue

            # Si lo encuentra, retorna el nombre que corresponde al endpoint
            if final_url in str(self_hosted[key_]):
                cms_self = key_
        
        # Retorna el nombre del endpoint por ejemplo Wordpress
        return cms_self
    
    # Funcion encargada de testear endpoints self hosted
    def test_api_self(url_):

        # Obtenemos el nombre del endpoint
        cms_add = detect_api(url_)

        # Intentamos establecer conexion si no hay se omite el escaneo
        try:
            query_ = requests.get(url_, timeout=10)
        
        except KeyboardInterrupt:
            return

        except:
            return

        # Si el archivo contiene algun tag html o XML se omite
        if '="' in query_.text or "</" in query_.text:
            print(f"[INFO] Verificando CMS {cms_add} =>> [BAD]")
            return

        # Si el archivo no comienza con { se omite
        if not query_.text.startswith("{") and not query_.text.startswith("["):
            print(f"[INFO] Verificando CMS {cms_add} =>> [BAD]")
            return

        # Si el switch es verdadero es decir si el escaneo profundo comenzo
        if switch_:

            # Si la respuesta de la api es inferior a 100 caracteres se salta la iteracion
            if len(query_.text) < 100:
                print(f"[INFO] Verificando CMS {cms_add} =>> [BAD]")
                return
            
            # Si es mayor se guarda
            print(f"[PASS] Verificando CMS {cms_add} =>> [OK]")

            if url_ not in results_inf_[cms_add]:
                results_inf_[cms_add].append(url_)

            return

        # Si pasa los filtros anteriores es un endpoint expuesto
        print(f"[PASS] Verificando CMS {cms_add} =>> [OK]")

        # Si el nombre del endpoint ya esta registrado en la variable de guardado final
        # Aumentamos el contador de check en esa CMS y agregamos los endpoints
        if cms_add in results_inf_:
            results_inf_[cms_add].append(url_)
            return
        
        # Si no, se crea el arreglo con el nombre del endpoint, contador y endpoints
        results_inf_.setdefault(cms_add, [])
        results_inf_[cms_add].append(url_)

    # Obtenemos todos los endpoints a escanear y los almacenamos en to_scan para el escaneo
    for key_ in self_hosted.keys():

        for api_rest_endpoint in self_hosted[key_]:
            to_scan.append(url_ + api_rest_endpoint)

    # Realizamos el escaneo con un maximo de 10 hilos
    try:
        with ThreadPoolExecutor(max_workers=10) as th_:
            th_.map(test_api_self, to_scan)

    except Exception as err:
        print(f"[ERROR] {err}")
    
    # Si el escaneo es profundo y existe algun resultado en self hosted
    if deep_ and any(key_ in results_inf_ for key_ in self_hosted.keys()):
        print("\n[INFO] Iniciando escaneo de verificacion =>> [OK]")

        switch_ = True ######################################
        
        # Por cada elemento guardado en resultado final verificamos si es un CMS valido en Self Hosted Deep
        for key_ in results_inf_.keys():
            if key_ in deep_shosted:
                
                # Si es asi iteramos con el dentro de cada endpoint desde deep_hosted para agregarlo a deep_scan
                for end_p in deep_shosted[key_]:
                    deep_scan.append(url_ + end_p)

        # Intentamos iterar sobre la lista que contiene los endpoints
        try:
            with ThreadPoolExecutor(max_workers=10) as th_:
                th_.map(test_api_self, deep_scan)
        
        except Exception as err:
            print(f"[ERROR] {err}")

    if not results_inf_:
        print(f"[ERROR] No se logro encontrar ningun CMS =>> [BAD]")
        return
    
    print("""
----------------------------------
:: CMS DETECTOR =>> BETA $SHELL ::
----------------------------------""")
    
    doc_urls = all_json[3]
    all_str_endpints_self = ""
    all_code_html_cms = ""

    # Se recorre cada llave dentro de los resultados verificando si existen resultados
    for key_ in results_inf_.keys():

        if type(results_inf_[key_]) == list:
            
            # Si existen resultados en cms selfhosted se muestra y se almacena en un str totalmente inecesario pero funcional
            if key_ in self_hosted:
                print(f":: CMS {key_.upper()} total: {len(results_inf_[key_])}")
                print(f":: CMS Documentation: {doc_urls[key_]}")
                all_str_endpints_self = all_str_endpints_self + "\n----------------------------------\n:: "+key_.upper()+"\n----------------------------------\n"
                
                for url_to in results_inf_[key_]:
                    all_str_endpints_self = all_str_endpints_self + url_to + "\n"

            # Si existen resultados en cms SaaS se muestra y se almacena en un str totalmente inecesario pero funcional igual que el de arriba
            if key_ in saas:
                print(f":: CMS SaaS panel: {key_.upper()}")
                print(f":: In Code SaaS API: {len(results_inf_[key_])}")
                print(f":: CMS Documentation: {doc_urls[key_]}")
                all_code_html_cms = all_code_html_cms + "\n----------------------------------\n:: "+key_.upper()+"\n----------------------------------\n"

                for url_to in results_inf_[key_]:
                    all_code_html_cms = all_code_html_cms + url_to + "\n"

            print(all_str_endpints_self)
    
    with open("save_report.txt", "w", encoding="utf-8") as save_:
        save_.write(all_str_endpints_self + "\n" + all_code_html_cms)

    print("[PASS] Endpoints guardados en =>> [save_report.txt]")

if __name__ == "__main__":

    url_to_find = input(""":: CMS DETECTOR =>> MIT LICENSE ::
> EX4MPL3: https://pagina.web.com/ --deep
                        
W3B-URL-T0-SC4N =>> """)
    apidetector(url_to_find, "deep" if "--deep" in url_to_find else None)