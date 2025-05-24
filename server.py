import os
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import unquote, urlparse, parse_qs
from datetime import datetime
import email
import email.policy
import email.utils

# --- Configuración Inicial del Sistema de Logging ---
# Configura el sistema de logging para registrar mensajes informativos y superiores.
# El formato incluye la marca de tiempo, el nivel del mensaje, el origen (SERVER) y el mensaje.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [SERVER] - %(message)s')

# --- Nueva Definición de Rutas y Variables Globales ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Directorio del script
USER_HOME = os.path.expanduser("~")  # Home del usuario
USER_DATA_DIR = os.path.join(USER_HOME, "Documents", "Pop3MailDownloader_UserData")  # Directorio base del usuario

# Asegúrate de que el directorio de datos del usuario existe
if not os.path.exists(USER_DATA_DIR):
    logging.info(f"Creando directorio de datos del usuario en: {USER_DATA_DIR}")
    os.makedirs(USER_DATA_DIR)

METADATA_FILE = os.path.join(USER_DATA_DIR, 'emails_metadata.json')  # Archivo de metadatos
CORREOS_BASE_DIR = os.path.join(USER_DATA_DIR, 'emails')  # Directorio base de emails
SPAM_SETTINGS_FILE = os.path.join(USER_DATA_DIR, 'spam_settings.json')  # Archivo de configuración de SPAM
DEFAULT_SPAM_SETTINGS = {
    "score_limit": 0,
    "blacklist_words": [],
    "blacklist_emails": [],
    "blacklist_domains": [],
    "whitelist_words": [],
    "whitelist_emails": [],
    "whitelist_domains": []
}

# Variable global para almacenar en memoria los metadatos de los correos una vez cargados.
# Se inicializa como None y se carga bajo demanda.
emails_metadata = None
spam_settings = None

# --- Funciones Auxiliares del Servidor ---

def _process_spam_config(config_dict, default_reference_config):
    """
    Procesa un diccionario de configuración de spam, asegurando que las listas
    sean sets de strings en minúsculas y que score_limit sea un entero.
    Utiliza default_reference_config para los valores y tipos predeterminados.
    """
    processed_config = {}

    # Procesar score_limit (debe ser un entero)
    raw_score_limit = config_dict.get("score_limit", default_reference_config["score_limit"])
    try:
        processed_config["score_limit"] = int(raw_score_limit)
    except (ValueError, TypeError):
        logging.warning(
            f"Valor de score_limit ('{raw_score_limit}') no es un entero válido. "
            f"Usando por defecto: {default_reference_config['score_limit']}."
        )
        processed_config["score_limit"] = default_reference_config["score_limit"]

    # Procesar todas las claves que se esperan como listas (se convertirán a sets)
    list_keys = [
        "blacklist_words", "blacklist_emails", "blacklist_domains",
        "whitelist_words", "whitelist_emails", "whitelist_domains"
    ]
    for key in list_keys:
        # Obtener el valor del config_dict, o del default_reference_config si no está en config_dict,
        # o una lista vacía como último recurso.
        default_list_value = default_reference_config.get(key, [])
        raw_list_value = config_dict.get(key, default_list_value)

        if not isinstance(raw_list_value, list):
            logging.warning(
                f"Valor para '{key}' en la configuración de spam no es una lista. "
                f"Se usará la lista predeterminada/vacía: {default_list_value}."
            )
            raw_list_value = default_list_value # Usar la lista predeterminada o vacía
        
        # Convertir cada elemento a string, luego a minúsculas, y finalmente a un set.
        processed_config[key] = set(str(item).lower() for item in raw_list_value)
        
    # Asegurar que todas las claves de default_reference_config estén en processed_config
    for key, default_val in default_reference_config.items():
        if key not in processed_config:
            if isinstance(default_val, list):
                processed_config[key] = set(str(item).lower() for item in default_val)
            else: # Para score_limit, ya manejado, pero por completitud.
                processed_config[key] = default_val

    return processed_config

def load_metadata():
    """
    Carga los metadatos de los correos electrónicos desde el archivo JSON configurado.
    Actualiza la variable global `emails_metadata`.
    Gestiona la ausencia del archivo y los errores de formato JSON para asegurar la robustez.
    Retorna True si la carga fue exitosa, False en caso contrario.
    """
    global emails_metadata
    logging.info(f"Iniciando carga de metadatos desde: '{METADATA_FILE}'.")
    
    if not os.path.exists(METADATA_FILE):
        logging.warning(f"Archivo de metadatos no encontrado en '{METADATA_FILE}'. Inicializando metadatos vacíos.")
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False
    
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            emails_metadata = json.load(f)
        logging.info(f"Metadatos cargados exitosamente. Total de registros de correos: {emails_metadata.get('total_emails', 0)}.")
        return True
    except json.JSONDecodeError:
        logging.error(f"Error de formato JSON al decodificar '{METADATA_FILE}'. Verifique la integridad del archivo.")
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False
    except Exception as e:
        logging.critical(f"Error inesperado al cargar metadatos desde '{METADATA_FILE}': {e}", exc_info=True)
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False

def load_spam_settings():
    """
    Carga la configuración del filtro de spam desde un archivo JSON.
    Si el archivo no existe o hay un error, usa la configuración predeterminada.
    La configuración cargada (o la predeterminada) se procesa para que las listas
    sean sets de strings en minúsculas y score_limit sea un entero.
    """
    global spam_settings
    logging.info(f"Cargando configuración de spam desde '{SPAM_SETTINGS_FILE}'")

    processed_default_settings = _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)

    try:
        if not os.path.exists(SPAM_SETTINGS_FILE):
            logging.warning(f"Archivo de configuración de spam no encontrado en '{SPAM_SETTINGS_FILE}'. Usando configuración predeterminada procesada.")
            spam_settings = processed_default_settings
            return False 
        
        with open(SPAM_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            loaded_config_from_file = json.load(f)
        
        spam_settings = _process_spam_config(loaded_config_from_file, DEFAULT_SPAM_SETTINGS)
        logging.info(f"Configuración de spam cargada y procesada exitosamente desde archivo.")
        # logging.debug(f"Spam settings en uso: {spam_settings}") 
        return True

    except json.JSONDecodeError as e:
        logging.error(f"Error al decodificar el archivo de configuración de spam '{SPAM_SETTINGS_FILE}': {e}. Usando configuración predeterminada procesada.")
        spam_settings = processed_default_settings
        return False
    except Exception as e:
        logging.critical(f"Error inesperado al cargar la configuración de spam desde '{SPAM_SETTINGS_FILE}': {e}", exc_info=True)
        spam_settings = processed_default_settings
        return False

def determine_email_spam_status(email_data, current_spam_settings):
    """
    Determina si un correo es spam basado en email_data y la configuración de spam procesada.
    Devuelve True si es spam, False en caso contrario.
    """
    score_limit = current_spam_settings.get("score_limit", 5) 
    whitelist_emails = current_spam_settings.get("whitelist_emails", set())
    whitelist_domains = current_spam_settings.get("whitelist_domains", set())
    blacklist_emails = current_spam_settings.get("blacklist_emails", set())
    blacklist_domains = current_spam_settings.get("blacklist_domains", set())
    whitelist_words = current_spam_settings.get("whitelist_words", set())
    blacklist_words = current_spam_settings.get("blacklist_words", set())

    sender_full_email = email_data.get('sender', '')
    sender_email_lower = ''
    sender_domain = ''
    subject_lower = str(email_data.get('subject', '')).lower()

    if sender_full_email and isinstance(sender_full_email, str):
        sender_email_lower = sender_full_email.lower()
        if '@' in sender_email_lower:
            parts = sender_email_lower.split('@', 1)
            if len(parts) > 1 and parts[1]: 
                 sender_domain = parts[1]

    # 1. Whitelists de spam_settings (MÁXIMA PRIORIDAD)
    # 1a. Por remitente (email/dominio)
    if (sender_email_lower and sender_email_lower in whitelist_emails) or \
       (sender_domain and sender_domain in whitelist_domains):
        return False # No es spam
    # 1b. Por palabras clave en el asunto
    if any(word in subject_lower for word in whitelist_words):
        return False # No es spam

    # 2. Blacklists de spam_settings
    # 2a. Por remitente (email/dominio)
    if (sender_email_lower and sender_email_lower in blacklist_emails) or \
       (sender_domain and sender_domain in blacklist_domains):
        return True # Es spam
    # 2b. Por palabras clave en el asunto
    if any(word in subject_lower for word in blacklist_words):
        return True # Es spam

    # 3. Campos preexistentes en metadata (spam_filter_whitelist tiene prioridad sobre spam_filter)
    if email_data.get('spam_filter_whitelist', 'no').lower() == 'yes': return False
    if email_data.get('spam_filter', 'no').lower() == 'yes': return True
        
    # 4. Spam score
    current_spam_score_raw = email_data.get('spam_score')
    if current_spam_score_raw is not None:
        try:
            if float(current_spam_score_raw) > score_limit: return True
        except (ValueError, TypeError): pass 
            
    return False # Por defecto, no es spam

# --- Clase Manejadora de Solicitudes HTTP ---

class RequestHandler(BaseHTTPRequestHandler):
    """
    Manejador de solicitudes HTTP personalizado. Extiende BaseHTTPRequestHandler para
    servir archivos estáticos, listar metadatos de correos, y gestionar la visualización,
    lectura y descarga de archivos .eml.
    """

    def log_message(self, format, *args):
        """
        Sobrescribe el método log_message para suprimir los mensajes de registro
        de acceso HTTP por defecto, manteniendo los logs del servidor más limpios.
        """
        return

    def do_GET(self):
        """
        Maneja todas las solicitudes HTTP GET entrantes.
        Analiza la URL solicitada y enruta la petición a la función de manejo apropiada.
        """
        logging.info(f"Petición GET recibida para la ruta: '{self.path}'.")
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)

        if path == '/' or path == '/index.html':
            logging.info("Ruta solicitada: Página principal. Sirviendo 'index.html'.")
            self.serve_static_file('index.html')
        elif path == '/list-eml':
            logging.info("Ruta solicitada: Listado de correos. Procesando petición de metadatos.")
            self.list_eml_files_from_metadata(query_params)
        elif path.startswith('/read-eml'):
            logging.info("Ruta solicitada: Lectura de archivo .eml (texto plano).")
            self.read_eml_file()
        elif path.startswith('/download-eml'):
            logging.info("Ruta solicitada: Descarga de archivo .eml.")
            self.download_eml_file()
        elif path.startswith('/view-html-eml'):
            logging.info("Ruta solicitada: Vista previa HTML de archivo .eml.")
            self.view_html_eml_file()
        else:
            logging.warning(f"Recurso no encontrado para la ruta: '{self.path}'. Respondiendo con 404.")
            self.send_error(404, "Recurso No Encontrado")

    def serve_static_file(self, filename):
        """
        Sirve un archivo estático desde el sistema de archivos local.
        Determina el Content-Type adecuado basado en la extensión del archivo.
        """
        file_path_to_serve = os.path.join(SCRIPT_DIR, filename)
        logging.info(f"Intentando servir archivo estático: '{file_path_to_serve}'.")
        try:
            content_type = 'application/octet-stream' 
            if filename.endswith('.html'):
                content_type = 'text/html'
            elif filename.endswith('.css'):
                content_type = 'text/css'
            elif filename.endswith('.js'):
                content_type = 'application/javascript'
            elif filename.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                content_type = f'image/{filename.split(".")[-1]}'

            with open(file_path_to_serve, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.end_headers()
            self.wfile.write(content)
            logging.info(f"Archivo estático '{file_path_to_serve}' servido correctamente con Content-Type: {content_type}.")

        except FileNotFoundError:
            logging.error(f"Error: El archivo estático '{file_path_to_serve}' no fue encontrado.")
            self.send_error(404, "Archivo No Encontrado")
        except Exception as e:
            logging.error(f"Error inesperado al servir el archivo estático '{file_path_to_serve}': {e}", exc_info=True)
            self.send_error(500, "Error Interno del Servidor al servir el archivo.")

    def list_eml_files_from_metadata(self, query_params):
        """
        Carga y envía los metadatos de todos los correos electrónicos en formato JSON.
        Esta función es utilizada por el frontend para poblar la tabla principal.
        """
        global emails_metadata, spam_settings # Ensure spam_settings is accessible
        load_metadata()

        # spam_settings global ya está procesado y listo para usar.
        # Si spam_settings no se cargó (ej. error al inicio), determine_email_spam_status usará sus propios fallbacks.

        processed_emails = []
        if emails_metadata and 'emails' in emails_metadata:
            for email_data in emails_metadata['emails']:
                # Asegurarse de que spam_settings no sea None antes de pasarlo.
                # Si es None, significa que la carga inicial falló críticamente.
                # En tal caso, determine_email_spam_status debería usar DEFAULT_SPAM_SETTINGS
                # o su propia lógica interna de fallback si current_spam_settings es None.
                # Para ser más explícito, podemos pasar DEFAULT_SPAM_SETTINGS si spam_settings es None.
                current_settings_to_use = spam_settings if spam_settings is not None else _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)
                email_data['is_spam'] = determine_email_spam_status(email_data, current_settings_to_use)
                processed_emails.append(email_data)

        response_data = {
            'emails': processed_emails,
            'total_emails': emails_metadata.get('total_emails', 0),
            'page': 1,
            'limit': emails_metadata.get('total_emails', 0)
        }

        logging.info(f"Preparando respuesta JSON con {len(response_data['emails'])} registros de metadatos de correos.")
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_content = json.dumps(response_data, indent=4)
        self.wfile.write(response_content.encode('utf-8'))
        logging.info("Respuesta JSON con metadatos de correos enviada exitosamente.")

    def read_eml_file(self):
        """
        Lee el contenido de un archivo .eml especificado por el parámetro 'path' en la URL
        y lo envía como texto plano en la respuesta HTTP.
        """
        full_path = self.get_path_from_query()
        if not full_path:
            logging.error("Solicitud de lectura de .eml rechazada: Ruta de archivo no válida o ausente.")
            self.send_error(400, "Ruta de archivo no válida o ausente.")
            return

        logging.info(f"Intentando leer el contenido (texto plano) del archivo .eml: '{full_path}'.")

        if not os.path.exists(full_path):
            logging.error(f"Error de lectura de .eml: Archivo no encontrado en la ruta: '{full_path}'.")
            self.send_error(404, f"Archivo no encontrado: {os.path.basename(full_path)}")
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.wfile.write(content.encode('utf-8')) 
            logging.info(f"Contenido del archivo '{os.path.basename(full_path)}' leído y enviado como texto plano.")

        except Exception as e:
            logging.error(f"Error al leer el archivo '{os.path.basename(full_path)}' para visualización en texto plano: {e}", exc_info=True)
            self.send_error(500, "Error interno del servidor al leer el archivo.")

    def download_eml_file(self):
        """
        Permite la descarga de un archivo .eml especificado por el parámetro 'path' en la URL.
        Establece el encabezado Content-Disposition para forzar al navegador a descargar el archivo.
        """
        full_path = self.get_path_from_query()
        if not full_path:
            logging.error("Solicitud de descarga de .eml rechazada: Ruta de archivo no válida o ausente.")
            self.send_error(400, "Ruta de archivo no válida o ausente.")
            return

        logging.info(f"Preparando archivo .eml para descarga: '{full_path}'.")

        if not os.path.exists(full_path):
            logging.error(f"Error de descarga de .eml: Archivo no encontrado en la ruta: '{full_path}'.")
            self.send_error(404, f"Archivo no encontrado: {os.path.basename(full_path)}")
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream') 
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(full_path)}"')
        self.end_headers()

        try:
            with open(full_path, 'rb') as f:
                self.wfile.write(f.read())
            logging.info(f"Archivo '{os.path.basename(full_path)}' enviado exitosamente para descarga.")

        except Exception as e:
            logging.error(f"Error al leer el archivo '{os.path.basename(full_path)}' durante la descarga: {e}", exc_info=True)
            self.send_error(500, "Error interno del servidor durante la descarga del archivo.")

    def view_html_eml_file(self):
        """
        Genera una vista previa HTML de un archivo .eml.
        Extrae el contenido HTML o de texto plano del correo y lo incrusta en una estructura HTML básica.
        Implementa la nueva lógica de detección de SPAM y muestra los campos 'Para' y 'CC'.
        """
        global spam_settings # Ensure spam_settings is accessible
        rel_path_encoded = urlparse(self.path).query
        query_params = parse_qs(rel_path_encoded)
        rel_path = None
        if 'path' in query_params and query_params['path']:
            rel_path = unquote(query_params['path'][0])

        if not rel_path:
            logging.error("Solicitud de vista previa HTML de .eml rechazada: Parámetro 'path' no válido o ausente.")
            self.send_error(400, "No se proporcionó un parámetro 'path' válido.")
            return

        base_dir_emails = CORREOS_BASE_DIR
        normalized_rel_path_for_join = os.path.normpath(rel_path)
        full_path = os.path.join(base_dir_emails, normalized_rel_path_for_join)

        if not os.path.realpath(full_path).startswith(os.path.realpath(base_dir_emails)):
            logging.warning(f"Intento de acceso no autorizado fuera del directorio base detectado: '{full_path}'. Solicitud rechazada.")
            self.send_error(403, "Acceso denegado a la ruta especificada.")
            return

        logging.info(f"Procesando archivo .eml para generar vista previa HTML: '{full_path}'.")

        if not os.path.exists(full_path):
            logging.error(f"Error de vista previa HTML de .eml: Archivo no encontrado en la ruta: '{full_path}'.")
            self.send_error(404, f"Archivo no encontrado: {full_path}")
            return

        if not load_metadata():
            logging.error("Fallo al cargar metadatos para generar la vista previa HTML. No se puede continuar.")
            error_html = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error al Cargar Metadatos</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; text-align: center; }
                    h1 { color: #e74c3c; }
                </style>
            </head>
            <body>
                <h1>Error al Cargar Metadatos</h1>
                <p>No se pudieron cargar los Correos Electrónicos. Por favor, revise los registros del servidor para más detalles.</p>
            </body>
            </html>
            """
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(error_html.encode('utf-8'))
            return

        email_metadata = None
        normalized_rel_path = rel_path.replace('\\', '/') 
        for email_entry in emails_metadata.get('emails', []):
            normalized_metadata_path = email_entry.get('path', '').replace('\\', '/')
            if normalized_metadata_path == normalized_rel_path:
                email_metadata = email_entry
                break

        if not email_metadata:
            logging.warning(f"No se encontraron metadatos para la ruta de correo: '{rel_path}'. El archivo 'emails_metadata.json' podría no estar actualizado.")
            error_html = f"""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Correo Electrónico no Encontrado en Metadatos</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; text-align: center; }}
                    h1 {{ color: #e74c3c; }}
                </style>
            </head>
            <body>
                <h1>Correo Electrónico no Encontrado en Metadatos</h1>
                <p>No se encontraron metadatos para el Correo Electrónico solicitado en la ruta: {rel_path}.</p>
                <p>Asegúrate de que el archivo exista y que el archivo emails_metadata.json esté actualizado.</p>
            </body>
            </html>
            """
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(error_html.encode('utf-8'))
            return

        subject_header = email_metadata.get('subject', 'Sin asunto')
        from_header = email_metadata.get('sender', 'Remitente desconocido')
        account_recipient_header = email_metadata.get('recipient', 'Cuenta desconocida')
        to_recipients = email_metadata.get('to', [])
        cc_recipients = email_metadata.get('cc', [])
        date_str = email_metadata.get('date', 'Fecha desconocida')
        time_str = email_metadata.get('time', 'Hora desconocida')
        formatted_date_time = f"{date_str.replace('-', '/') if date_str and date_str != 'Fecha desconocida' else 'Fecha desconocida'} {time_str.replace('-', ':') if time_str and time_str != 'Hora desconocida' else 'Hora desconocida'}"
        
        current_settings_to_use = spam_settings if spam_settings is not None else _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)
        is_spam = determine_email_spam_status(email_metadata, current_settings_to_use)
        spam_score_for_modal = email_metadata.get('spam_score') 

        html_content = None
        text_content = None
        charset = 'utf-8'

        try:
            with open(full_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)

            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = part.get('Content-Disposition')

                if cdisp and cdisp.startswith('attachment'):
                    continue

                if ctype == 'text/html':
                    try:
                        charset = part.get_content_charset() or charset
                        html_content = part.get_payload(decode=True).decode(charset, errors='replace')
                        logging.info(f"Contenido HTML extraído y decodificado para '{os.path.basename(full_path)}'.")
                        break 
                    except Exception as e:
                        logging.warning(f"Error al decodificar la parte HTML del correo '{os.path.basename(full_path)}' (Charset: {charset}): {e}. Intentando con texto plano si está disponible.")
                        html_content = "<p>Error al decodificar el contenido HTML.</p>"

                if ctype == 'text/plain' and text_content is None:
                    try:
                        charset = part.get_content_charset() or charset
                        text_content = part.get_payload(decode=True).decode(charset, errors='replace')
                        logging.info(f"Contenido de texto plano extraído y decodificado para '{os.path.basename(full_path)}'.")
                    except Exception as e:
                        logging.warning(f"Error al decodificar la parte de texto plano del correo '{os.path.basename(full_path)}' (Charset: {charset}): {e}.")
                        text_content = "Error al decodificar el contenido de texto plano."

        except Exception as e:
            logging.error(f"Ocurrió un error general al parsear el archivo .eml '{os.path.basename(full_path)}': {e}", exc_info=True)
            html_content = None
            text_content = "Error crítico al leer el contenido del Correo Electrónico. Verifique la integridad del archivo .eml."

        download_url = f"/download-eml?path={query_params['path'][0]}"

        final_html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vista Previa del Correo Electrónico: {subject_header}</title>
    <style>
        html, body {{
            height: 100%;
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background-color: #f4f7f6;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            overflow: hidden;
            width: 100%;
        }}
        .main-container {{
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            padding: 10px;
            box-sizing: border-box;
            overflow: hidden;
            width: 100%;
        }}
        .preview-header-actions {{
            display: flex;
            align-items: center; 
            gap: 15px; 
            margin-bottom: 10px;
            flex-wrap: wrap; 
            justify-content: space-between; 
            padding: 10px;
            background-color: #e0e0e0; 
            border-radius: 8px;
        }}
        .preview-message {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
            padding: 10px;
            text-align: center;
            font-size: 1.1em;
            font-weight: bold;
            border-radius: 5px;
            flex-grow: 1; 
            min-width: 250px; 
        }}
        .spam-warning-message {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 10px;
            margin-bottom: 10px;
            text-align: center;
            font-size: 1em;
            font-weight: bold;
            border-radius: 5px;
            flex-shrink: 0;
        }}
        .scrollable-email-content {{
            border: 5px solid #bdc3c7;
            border-radius: 8px;
            overflow: auto;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            padding: 15px;
            background-color: #ffffff;
            box-sizing: border-box;
            min-height: 0;
            width: 100%;
        }}
        .email-details-preview {{
            display: flex; 
            justify-content: space-between; 
            align-items: flex-start; 
            flex-wrap: wrap; 
            padding: 0 0 15px 0;
            margin: 0;
            word-wrap: break-word;
            flex-shrink: 0;
        }}
        .email-details-preview .left-details,
        .email-details-preview .right-details {{
            display: flex;
            flex-direction: column; 
            gap: 5px; 
        }}
        .email-details-preview .left-details {{
            flex-grow: 1; 
            flex-basis: 60%; 
            min-width: 250px; 
        }}
        .email-details-preview .right-details {{
            flex-basis: 35%; 
            text-align: right; 
            min-width: 150px; 
        }}
        .email-details-preview .detail-pair {{
            display: block;
            text-align: left; 
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        .email-details-preview .right-details .detail-pair {{
            text-align: right;
        }}
         .email-details-preview strong {{
            color: #555;
            display: inline;
            word-wrap: break-word;
            overflow-wrap: break-word;
            margin-right: 5px;
        }}
        .email-details-preview .detail-value {{
            word-wrap: break-word;
            overflow-wrap: break-word;
            white-space: pre-wrap;
            max-width: 100%;
            min-width: 0;
            display: inline;
        }}
        .email-body-container {{
            border: none;
            border-radius: 0;
            padding: 0;
            margin: 0;
            flex-grow: 1;
            overflow: visible;
            word-wrap: break-word;
            min-height: 0;
        }}
        .download-button-header {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            text-decoration: none;
            transition: background-color 0.3s ease;
            font-weight: bold;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            vertical-align: middle;
            flex-shrink: 0; 
        }}
        .download-button-header:hover {{
            background-color: #2980b9;
            color: white;
        }}
        .download-button-header:active {{
            background-color: #2573a7;
            color: white;
        }}
        #previewSpamModalOverlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.6);
            z-index: 2000;
            justify-content: center;
            align-items: center;
        }}
        #previewSpamModalOverlay .modal-content {{
            background-color: #fdecea;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            max-width: 850px;
            width: fit-content;
            min-width: 350px;
            text-align: center;
            position: relative;
        }}
        #previewSpamModalOverlay .modal-message {{
            font-size: 1.1em;
            color: #721c24;
            margin-bottom: 20px;
            font-weight: bold;
        }}
        #previewSpamModalOverlay .modal-buttons {{
            display: flex;
            justify-content: center;
            gap: 15px;
        }}
        #previewSpamModalOverlay .modal-buttons button {{
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: background-color 0.3s ease;
        }}
        #previewSpamModalOverlay .modal-buttons button#previewConfirmDownloadBtn {{
            background-color: #e74c3c; color: white;
        }}
        #previewSpamModalOverlay .modal-buttons button#previewCancelDownloadBtn {{
            background-color: #bdc3c7; color: #333;
        }}
        @media (max-width: 600px) {{
            .main-container {{ padding: 5px; }}
            .preview-header-actions {{ flex-direction: column; align-items: stretch; gap: 10px; padding: 8px; }}
            .preview-message, .spam-warning-message {{ padding: 8px; margin-bottom: 0; flex-grow: 0; min-width: unset; }}
            .scrollable-email-content {{ padding: 10px; border-width: 3px; }}
            .email-details-preview {{ flex-direction: column; align-items: stretch; gap: 8px; padding-bottom: 10px; }}
            .email-details-preview .left-details, .email-details-preview .right-details {{ flex-basis: auto; min-width: unset; text-align: left; }}
            .email-details-preview .right-details .detail-pair {{ text-align: left; }}
            #previewSpamModalOverlay .modal-content {{ padding: 15px; }}
            #previewSpamModalOverlay .modal-message {{ font-size: 1em; }}
            #previewSpamModalOverlay .modal-buttons {{ flex-direction: column; gap: 10px; }}
            #previewSpamModalOverlay .modal-buttons button {{ width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="main-container">
        <div class="preview-header-actions">
            <div class="preview-message">
                Esta es una representación simplificada del Correo Electrónico. Para visualizar el contenido completo con su formato original, por favor descargue el archivo.
            </div>
            <a id="downloadPreviewBtn" href="{download_url}" class="download-button-header" download>Descargar Correo Electrónico</a>
        </div>
        {
            '<div class="spam-warning-message">¡Advertencia!<br>Este correo ha sido identificado como SPAM.<br>Se recomienda precaución al interactuar con su contenido, ya que podría comprometer su información personal.</div>'
            if is_spam else ''
        }
        <div class="scrollable-email-content">
            <div class="email-details-preview">
                <div class="left-details">
                    <div class="detail-pair">
                        <strong>Fecha y Hora:</strong> <span class="detail-value">{formatted_date_time}</span>
                    </div>
                    <div class="detail-pair">
                        <strong>De:</strong> <span class="detail-value">{from_header}</span>
                    </div>
                    {
                        '<div class="detail-pair">'
                        '<strong>Para:</strong> <span class="detail-value">' + (', '.join(to_recipients) if to_recipients else 'N/A') + '</span>'
                        '</div>'
                    }
                    {
                        '<div class="detail-pair">'
                        '<strong>CC:</strong> <span class="detail-value">' + (', '.join(cc_recipients) if cc_recipients else 'N/A') + '</span>'
                        '</div>'
                    }
                    <div class="detail-pair">
                        <strong>Asunto:</strong> <span class="detail-value">{subject_header}</span>
                    </div>
                </div>
                <div class="right-details">
                    <div class="detail-pair">
                        <strong>Cuenta:</strong> <span class="detail-value">{account_recipient_header}</span>
                    </div>
                </div>
            </div>
            <div class="email-body-container">
"""
        if html_content:
            final_html_content += html_content
        elif text_content:
            final_html_content += f"<pre>{text_content}</pre>"
        else:
            final_html_content += "<p>No se encontró contenido visualizable en este Correo Electrónico.</p>"

        final_html_content += """
            </div>
        </div>
    </div>
"""
        if is_spam:
            final_html_content += f"""
    <div id="previewSpamModalOverlay" style="display: none;">
        <div class="modal-content">
            <p class="modal-message">
                Alerta de Seguridad.<br>Este Correo Electrónico está marcado como SPAM.<br>
                Puntuación de Spam: {spam_score_for_modal if spam_score_for_modal is not None else 'N/A'}<br>
                Descargarlo podría exponer su dispositivo a software malicioso o revelar información personal.<br>¿Desea continuar bajo su propio riesgo?
            </p>
            <div class="modal-buttons">
                <button id="previewConfirmDownloadBtn">Descargar de todos modos</button>
                <button id="previewCancelDownloadBtn">Cancelar</button>
            </div>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const downloadBtn = document.getElementById('downloadPreviewBtn');
            const spamModal = document.getElementById('previewSpamModalOverlay');
            const confirmDownloadBtn = document.getElementById('previewConfirmDownloadBtn');
            const cancelDownloadBtn = document.getElementById('previewCancelDownloadBtn');

            if (downloadBtn && spamModal && confirmDownloadBtn && cancelDownloadBtn) {{
                downloadBtn.addEventListener('click', function(event) {{
                    event.preventDefault(); 
                    spamModal.style.display = 'flex'; 
                }});
                confirmDownloadBtn.addEventListener('click', function() {{
                    spamModal.style.display = 'none'; 
                    window.location.href = downloadBtn.href; 
                }});
                cancelDownloadBtn.addEventListener('click', function() {{
                    spamModal.style.display = 'none'; 
                }});
            }}
        }});
    </script>
"""
        final_html_content += """
</body>
</html>
"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(final_html_content.encode('utf-8'))
        logging.info(f"Vista previa HTML del correo '{os.path.basename(full_path)}' generada y enviada exitosamente.")


    def get_path_from_query(self):
        """
        Extrae y valida el parámetro 'path' de la cadena de consulta de la URL.
        Implementa una medida de seguridad para prevenir ataques de 'Directory Traversal',
        asegurando que la ruta solicitada esté dentro del directorio base permitido.
        Retorna la ruta completa y validada del archivo, o None si es inválida o ausente.
        """
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        path = None
        if 'path' in query_params and query_params['path']:
            path = unquote(query_params['path'][0]) 

        if not path:
            logging.warning("El parámetro 'path' está ausente o vacío en la cadena de consulta.")
            return None

        base_dir_emails = CORREOS_BASE_DIR
        full_path = os.path.normpath(os.path.join(base_dir_emails, path))

        if not os.path.realpath(full_path).startswith(os.path.realpath(base_dir_emails)):
            logging.warning(f"Intento de acceso no autorizado detectado: La ruta solicitada '{full_path}' está fuera del directorio base permitido '{base_dir_emails}'.")
            return None

        logging.debug(f"Ruta de archivo validada: '{full_path}'.")
        return full_path

# --- Bloque Principal de Ejecución del Script ---

if __name__ == '__main__':
    load_metadata()  
    load_spam_settings() 

    server_address = ('0.0.0.0', 8000)
    server = HTTPServer(server_address, RequestHandler)

    logging.info(f'Servidor HTTP iniciado y escuchando en http://{server_address[0]}:{server_address[1]}.')
    logging.info('El servidor es accesible en la red local. Presione Ctrl+C para detenerlo.')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info('Señal de interrupción (Ctrl+C) recibida. Iniciando apagado ordenado del servidor...')
        server.shutdown() 
        logging.info('Servidor HTTP detenido correctamente.')
    except Exception as e:
        logging.critical(f"Ocurrió un error crítico e inesperado en el bucle principal del servidor: {e}", exc_info=True)
