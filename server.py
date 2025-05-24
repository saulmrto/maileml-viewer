import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import unquote, urlparse, parse_qs
import email
import email.policy

# --- Global Path Definitions and Variables ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USER_HOME = os.path.expanduser("~")
USER_DATA_DIR = os.path.join(USER_HOME, "Documents", "Pop3MailDownloader_UserData")

# Ensure the user data directory exists
if not os.path.exists(USER_DATA_DIR):
    os.makedirs(USER_DATA_DIR)

METADATA_FILE = os.path.join(USER_DATA_DIR, 'emails_metadata.json')
CORREOS_BASE_DIR = os.path.join(USER_DATA_DIR, 'emails')
SPAM_SETTINGS_FILE = os.path.join(USER_DATA_DIR, 'spam_settings.json')
SETTINGS_FILE = os.path.join(USER_DATA_DIR, 'settings.json') # New settings file

DEFAULT_SPAM_SETTINGS = {
    "score_limit": 0,
    "blacklist_words": [],
    "blacklist_emails": [],
    "blacklist_domains": [],
    "whitelist_words": [],
    "whitelist_emails": [],
    "whitelist_domains": []
}

emails_metadata = None
spam_settings = None
current_lang = "en" # Default language, will be updated by load_settings()

# --- Translatable messages for server-side console logs and error pages ---
SERVER_MESSAGES = {
    "en": {
        "creating_user_data_dir": "INFO: Creating user data directory: {dir}",
        "loading_metadata_attempt": "INFO: Attempting to load metadata from: {file}",
        "metadata_file_not_found": "WARNING: Metadata file not found at {file}. Initializing with empty data.",
        "metadata_load_success": "INFO: Successfully loaded {count} emails from metadata.",
        "metadata_json_decode_error": "ERROR: Failed to decode JSON from metadata file: {error}. Initializing with empty data.",
        "metadata_load_unexpected_error": "ERROR: An unexpected error occurred while loading metadata: {error}. Initializing with empty data.",
        "loading_spam_settings_attempt": "INFO: Attempting to load spam settings from: {file}",
        "spam_settings_file_not_found": "WARNING: Spam settings file not found at {file}. Using default settings.",
        "spam_settings_load_success": "INFO: Successfully loaded and processed spam settings.",
        "spam_settings_json_decode_error": "ERROR: Failed to decode JSON from spam settings file: {error}. Using default settings.",
        "spam_settings_load_unexpected_error": "ERROR: An unexpected error occurred while loading spam settings: {error}. Using default settings.",
        "invalid_score_limit": "WARNING: Invalid 'score_limit' value '{value}'. Using default: {default}",
        "invalid_type_for_key": "WARNING: Invalid type for '{key}'. Expected list, got {type}. Using default.",
        "handling_get_request": "INFO: Handling GET request for path: {path}",
        "resource_not_found": "WARNING: Resource not found: {path}",
        "serving_static_file": "INFO: Serving static file: {file}",
        "static_file_served_success": "INFO: Successfully served {file} with Content-Type: {content_type}",
        "static_file_not_found": "ERROR: Static file not found: {file}",
        "static_file_server_error": "ERROR: Internal Server Error serving file {file}: {error}",
        "listing_eml_files": "INFO: Listing EML files from metadata.",
        "no_email_metadata_found": "WARNING: No email metadata found or 'emails' key is missing.",
        "sent_email_metadata_entries": "INFO: Sent {count} email metadata entries.",
        "reading_eml_file": "INFO: Attempting to read EML file: {file}",
        "invalid_or_missing_path_read": "ERROR: Invalid or missing file path for read-eml.",
        "file_not_found_read": "ERROR: File not found: {file}",
        "read_file_success": "INFO: Successfully read and sent content of {file}.",
        "read_file_server_error": "ERROR: Internal Server Error reading file {file}: {error}",
        "downloading_eml_file": "INFO: Attempting to download EML file: {file}",
        "invalid_or_missing_path_download": "ERROR: Invalid or missing file path for download-eml.",
        "file_not_found_download": "ERROR: File not found: {file}",
        "download_file_success": "INFO: Successfully sent {file} for download.",
        "download_file_server_error": "ERROR: Internal Server Error during file download from {file}: {error}",
        "viewing_html_eml_file": "INFO: Attempting to view HTML EML file for path: {path}",
        "no_valid_path_html_view": "ERROR: No valid 'path' parameter provided for HTML EML view.",
        "security_alert_traversal": "SECURITY ALERT: Potential directory traversal detected. Attempted path: {path}",
        "eml_file_not_found_html_view": "ERROR: EML file not found for HTML view: {file}",
        "metadata_loading_failed_html_view": "ERROR: Metadata loading failed during HTML EML view. Cannot proceed.",
        "email_metadata_not_found_html_view": "ERROR: Email metadata not found for path: {path}",
        "extracted_html_content": "INFO: Extracted HTML content for {file}.",
        "error_decoding_html_content": "WARNING: Error decoding HTML content from {file}: {error}",
        "extracted_plain_text_content": "INFO: Extracted plain text content for {file}.",
        "error_decoding_plain_text_content": "WARNING: Error decoding plain text content from {file}: {error}",
        "critical_error_parsing_eml": "ERROR: Critical error parsing EML file {file}: {error}",
        "path_validation_success": "INFO: Validated file path: {path}",
        "path_missing_or_empty": "WARNING: 'path' parameter is missing or empty in query.",
        "server_starting": "INFO: Starting server initialization.",
        "server_listening": "INFO: Server listening on {ip}:{port}...",
        "keyboard_interrupt": "INFO: KeyboardInterrupt detected. Shutting down server.",
        "server_unexpected_error": "CRITICAL ERROR: Server encountered an unexpected exception: {error}",
        "loading_settings_attempt": "INFO: Attempting to load settings from: {file}",
        "settings_file_not_found": "WARNING: Settings file not found at {file}. Creating default.",
        "settings_load_success": "INFO: Successfully loaded settings. Current language: {lang}",
        "invalid_lang_setting": "WARNING: Invalid 'lang' setting '{lang}'. Defaulting to 'en'.",
        "settings_json_decode_error": "ERROR: Failed to decode JSON from settings file: {error}. Defaulting to 'en'.",
        "settings_load_unexpected_error": "ERROR: An unexpected error occurred while loading settings: {error}. Defaulting to 'en'.",
        "sent_settings": "INFO: Sent settings to client. Language: {lang}",
        "error_page_metadata_title": "Metadata Loading Error",
        "error_page_metadata_message": "Could not load email metadata. Please check server logs for more details.",
        "error_page_email_not_found_title": "Email Not Found in Metadata",
        "error_page_email_not_found_message1": "No metadata found for the requested email at path: {path}.",
        "error_page_email_not_found_message2": "Ensure the file exists and emails_metadata.json is up-to-date.",
        "received_set_settings_request": "INFO: Received /set-settings request. New language: {lang}",
        "lang_setting_updated": "INFO: Language setting updated to: {lang}",
        "error_processing_set_settings": "ERROR: Error processing /set-settings request: {error}",
        "invalid_json_set_settings": "ERROR: Invalid JSON received for /set-settings: {error}",
        "preview_simplified_message": "This is a simplified representation of the email. To view the full content with its original formatting, please download the file.",
        "preview_download_button": "Download Email",
        "preview_spam_warning": "Warning!<br>This email has been identified as SPAM.<br>Exercise caution when interacting with its content, as it could compromise your personal information.",
        "preview_modal_security_alert": "Security Alert.",
        "preview_modal_spam_marked": "This Email is marked as SPAM.",
        "preview_modal_spam_score": "Spam Score:",
        "preview_modal_download_malicious_warning": "Downloading it could expose your device to malicious software or reveal personal information.",
        "preview_modal_continue_risk": "Do you wish to continue at your own risk?",
        "preview_modal_download_anyway": "Download Anyway",
        "preview_modal_cancel": "Cancel",
        "preview_date_time": "Date & Time:",
        "preview_from": "From:",
        "preview_to": "To:",
        "preview_cc": "CC:",
        "preview_subject": "Subject:",
        "preview_account": "Account:",
        "preview_no_content": "No viewable content found in this email."
    },
    "es": {
        "creating_user_data_dir": "INFO: Creando directorio de datos de usuario: {dir}",
        "loading_metadata_attempt": "INFO: Intentando cargar metadatos desde: {file}",
        "metadata_file_not_found": "ADVERTENCIA: Archivo de metadatos no encontrado en {file}. Inicializando con datos vacíos.",
        "metadata_load_success": "INFO: Se cargaron {count} correos electrónicos de los metadatos exitosamente.",
        "metadata_json_decode_error": "ERROR: Fallo al decodificar JSON del archivo de metadatos: {error}. Inicializando con datos vacíos.",
        "metadata_load_unexpected_error": "ERROR: Ocurrió un error inesperado al cargar metadatos: {error}. Inicializando con datos vacíos.",
        "loading_spam_settings_attempt": "INFO: Intentando cargar la configuración de spam desde: {file}",
        "spam_settings_file_not_found": "ADVERTENCIA: Archivo de configuración de spam no encontrado en {file}. Usando la configuración predeterminada.",
        "spam_settings_load_success": "INFO: Configuración de spam cargada y procesada exitosamente.",
        "spam_settings_json_decode_error": "ERROR: Fallo al decodificar JSON del archivo de configuración de spam: {error}. Usando la configuración predeterminada.",
        "spam_settings_load_unexpected_error": "ERROR: Ocurrió un error inesperado al cargar la configuración de spam: {error}. Usando la configuración predeterminada.",
        "invalid_score_limit": "ADVERTENCIA: Valor no válido para 'score_limit' '{value}'. Usando el predeterminado: {default}",
        "invalid_type_for_key": "ADVERTENCIA: Tipo no válido para '{key}'. Se esperaba una lista, se obtuvo {type}. Usando el predeterminado.",
        "handling_get_request": "INFO: Manejando solicitud GET para la ruta: {path}",
        "resource_not_found": "ADVERTENCIA: Recurso no encontrado: {path}",
        "serving_static_file": "INFO: Sirviendo archivo estático: {file}",
        "static_file_served_success": "INFO: Archivo {file} servido exitosamente con Content-Type: {content_type}",
        "static_file_not_found": "ERROR: Archivo estático no encontrado: {file}",
        "static_file_server_error": "ERROR: Error interno del servidor al servir el archivo {file}: {error}",
        "listing_eml_files": "INFO: Listando archivos EML desde metadatos.",
        "no_email_metadata_found": "ADVERTENCIA: No se encontraron metadatos de correo electrónico o falta la clave 'emails'.",
        "sent_email_metadata_entries": "INFO: Se enviaron {count} entradas de metadatos de correo electrónico.",
        "reading_eml_file": "INFO: Intentando leer archivo EML: {file}",
        "invalid_or_missing_path_read": "ERROR: Ruta de archivo no válida o faltante para leer EML.",
        "file_not_found_read": "ERROR: Archivo no encontrado: {file}",
        "read_file_success": "INFO: Contenido de {file} leído y enviado exitosamente.",
        "read_file_server_error": "ERROR: Error interno del servidor al leer el archivo {file}: {error}",
        "downloading_eml_file": "INFO: Intentando descargar archivo EML: {file}",
        "invalid_or_missing_path_download": "ERROR: Ruta de archivo no válida o faltante para descargar EML.",
        "file_not_found_download": "ERROR: Archivo no encontrado: {file}",
        "download_file_success": "INFO: Archivo {file} enviado para descarga exitosamente.",
        "download_file_server_error": "ERROR: Error interno del servidor durante la descarga del archivo desde {file}: {error}",
        "viewing_html_eml_file": "INFO: Intentando ver archivo EML HTML para la ruta: {path}",
        "no_valid_path_html_view": "ERROR: No se proporcionó un parámetro 'path' válido para la vista HTML EML.",
        "security_alert_traversal": "ALERTA DE SEGURIDAD: Intento de recorrido de directorio detectado. Ruta intentada: {path}",
        "eml_file_not_found_html_view": "ERROR: Archivo EML no encontrado para la vista HTML: {file}",
        "metadata_loading_failed_html_view": "ERROR: Fallo al cargar metadatos durante la vista HTML EML. No se puede continuar.",
        "email_metadata_not_found_html_view": "ERROR: Metadatos de correo electrónico no encontrados para la ruta: {path}",
        "extracted_html_content": "INFO: Contenido HTML extraído para {file}.",
        "error_decoding_html_content": "ADVERTENCIA: Error al decodificar contenido HTML de {file}: {error}",
        "extracted_plain_text_content": "INFO: Contenido de texto plano extraído para {file}.",
        "error_decoding_plain_text_content": "ADVERTENCIA: Error al decodificar contenido de texto plano de {file}: {error}",
        "critical_error_parsing_eml": "ERROR: Error crítico al analizar el archivo EML {file}: {error}",
        "path_validation_success": "INFO: Ruta de archivo validada: {path}",
        "path_missing_or_empty": "ADVERTENCIA: El parámetro 'path' falta o está vacío en la consulta.",
        "server_starting": "INFO: Iniciando la inicialización del servidor.",
        "server_listening": "INFO: Servidor escuchando en {ip}:{port}...",
        "keyboard_interrupt": "INFO: Interrupción de teclado detectada. Apagando el servidor.",
        "server_unexpected_error": "ERROR CRÍTICO: El servidor encontró una excepción inesperada: {error}",
        "loading_settings_attempt": "INFO: Intentando cargar la configuración desde: {file}",
        "settings_file_not_found": "ADVERTENCIA: Archivo de configuración no encontrado en {file}. Creando predeterminado.",
        "settings_load_success": "INFO: Configuración cargada exitosamente. Idioma actual: {lang}",
        "invalid_lang_setting": "ADVERTENCIA: Configuración de 'lang' no válida '{lang}'. Predeterminado a 'en'.",
        "settings_json_decode_error": "ERROR: Fallo al decodificar JSON del archivo de configuración: {error}. Predeterminado a 'en'.",
        "settings_load_unexpected_error": "ERROR: Ocurrió un error inesperado al cargar la configuración: {error}. Predeterminado a 'en'.",
        "sent_settings": "INFO: Configuración enviada al cliente. Idioma: {lang}",
        "error_page_metadata_title": "Error al Cargar Metadatos",
        "error_page_metadata_message": "No se pudieron cargar los metadatos del correo electrónico. Por favor, revise los registros del servidor para más detalles.",
        "error_page_email_not_found_title": "Correo Electrónico no Encontrado en Metadatos",
        "error_page_email_not_found_message1": "No se encontraron metadatos para el correo electrónico solicitado en la ruta: {path}.",
        "error_page_email_not_found_message2": "Asegúrese de que el archivo exista y que el archivo emails_metadata.json esté actualizado.",
        "received_set_settings_request": "INFO: Solicitud /set-settings recibida. Nuevo idioma: {lang}",
        "lang_setting_updated": "INFO: Configuración de idioma actualizada a: {lang}",
        "error_processing_set_settings": "ERROR: Error al procesar la solicitud /set-settings: {error}",
        "invalid_json_set_settings": "ERROR: JSON no válido recibido para /set-settings: {error}",
        "preview_simplified_message": "Esta es una representación simplificada del Correo Electrónico. Para visualizar el contenido completo, por favor descargue el archivo.",
        "preview_download_button": "Descargar Correo Electrónico",
        "preview_spam_warning": "¡Advertencia!<br>Este correo ha sido identificado como SPAM.<br>Se recomienda precaución al interactuar con su contenido, ya que podría comprometer su información personal.",
        "preview_modal_security_alert": "Alerta de Seguridad.",
        "preview_modal_spam_marked": "Este Correo Electrónico está marcado como SPAM.",
        "preview_modal_spam_score": "Puntuación de Spam:",
        "preview_modal_download_malicious_warning": "Descargarlo podría exponer su dispositivo a software malicioso o revelar información personal.",
        "preview_modal_continue_risk": "¿Desea continuar bajo su propio riesgo?",
        "preview_modal_download_anyway": "Descargar de todos modos",
        "preview_modal_cancel": "Cancelar",
        "preview_date_time": "Fecha y Hora:",
        "preview_from": "De:",
        "preview_to": "Para:",
        "preview_cc": "CC:",
        "preview_subject": "Asunto:",
        "preview_account": "Cuenta:",
        "preview_no_content": "No se encontró contenido visualizable en este Correo Electrónico."
    }
}

def get_server_message(key, **kwargs):
    """Retrieves a translated server message."""
    lang_messages = SERVER_MESSAGES.get(current_lang, SERVER_MESSAGES["en"])
    message = lang_messages.get(key, SERVER_MESSAGES["en"].get(key, f"MISSING_MESSAGE_KEY_{key}"))
    return message.format(**kwargs)

def _process_spam_config(config_dict, default_reference_config):
    """
    Processes a spam configuration dictionary.
    Ensures lists are converted to sets of lowercase strings and score_limit is an integer.
    Uses default_reference_config for default values and types.
    """
    processed_config = {}

    # Process score_limit (must be an integer)
    raw_score_limit = config_dict.get("score_limit", default_reference_config["score_limit"])
    try:
        processed_config["score_limit"] = int(raw_score_limit)
    except (ValueError, TypeError):
        print(get_server_message("invalid_score_limit", value=raw_score_limit, default=default_reference_config['score_limit']))
        processed_config["score_limit"] = default_reference_config["score_limit"]

    # Process all keys expected as lists (will be converted to sets)
    list_keys = [
        "blacklist_words", "blacklist_emails", "blacklist_domains",
        "whitelist_words", "whitelist_emails", "whitelist_domains"
    ]
    for key in list_keys:
        default_list_value = default_reference_config.get(key, [])
        raw_list_value = config_dict.get(key, default_list_value)

        if not isinstance(raw_list_value, list):
            print(get_server_message("invalid_type_for_key", key=key, type=type(raw_list_value).__name__))
            raw_list_value = default_list_value
        
        # Convert each item to a string, then to lowercase, and finally to a set.
        processed_config[key] = set(str(item).lower() for item in raw_list_value)
        
    # Ensure all keys from default_reference_config are in processed_config
    for key, default_val in default_reference_config.items():
        if key not in processed_config:
            if isinstance(default_val, list):
                processed_config[key] = set(str(item).lower() for item in default_val)
            else:
                processed_config[key] = default_val

    return processed_config

def load_metadata():
    """
    Loads email metadata from the configured JSON file.
    Updates the global `emails_metadata` variable.
    Manages file absence and JSON format errors for robustness.
    Returns True if loading was successful, False otherwise.
    """
    global emails_metadata
    print(get_server_message("loading_metadata_attempt", file=METADATA_FILE))
    
    if not os.path.exists(METADATA_FILE):
        print(get_server_message("metadata_file_not_found", file=METADATA_FILE))
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False
    
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            emails_metadata = json.load(f)
        print(get_server_message("metadata_load_success", count=len(emails_metadata.get('emails', []))))
        return True
    except json.JSONDecodeError as e:
        print(get_server_message("metadata_json_decode_error", error=e))
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False
    except Exception as e:
        print(get_server_message("metadata_load_unexpected_error", error=e))
        emails_metadata = {'emails': [], 'total_emails': 0}
        return False

def load_spam_settings():
    """
    Loads spam filter settings from a JSON file.
    If the file doesn't exist or there's an error, it uses default settings.
    The loaded (or default) configuration is processed so that lists
    are sets of lowercase strings and score_limit is an integer.
    """
    global spam_settings
    print(get_server_message("loading_spam_settings_attempt", file=SPAM_SETTINGS_FILE))

    processed_default_settings = _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)

    try:
        if not os.path.exists(SPAM_SETTINGS_FILE):
            print(get_server_message("spam_settings_file_not_found", file=SPAM_SETTINGS_FILE))
            spam_settings = processed_default_settings
            return False 
        
        with open(SPAM_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            loaded_config_from_file = json.load(f)
        
        spam_settings = _process_spam_config(loaded_config_from_file, DEFAULT_SPAM_SETTINGS)
        print(get_server_message("spam_settings_load_success"))
        return True

    except json.JSONDecodeError as e:
        print(get_server_message("spam_settings_json_decode_error", error=e))
        spam_settings = processed_default_settings
        return False
    except Exception as e:
        print(get_server_message("spam_settings_load_unexpected_error", error=e))
        spam_settings = processed_default_settings
        return False

def load_settings():
    """
    Loads application settings from a JSON file.
    Updates the global `current_lang` variable.
    """
    global current_lang
    print(get_server_message("loading_settings_attempt", file=SETTINGS_FILE))
    try:
        if not os.path.exists(SETTINGS_FILE):
            print(get_server_message("settings_file_not_found", file=SETTINGS_FILE))
            # Create a default settings.json if it doesn't exist
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"lang": "en"}, f, indent=4)
            current_lang = "en"
            return False
        
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings = json.load(f)
            if "lang" in settings and settings["lang"] in ["en", "es"]:
                current_lang = settings["lang"]
                print(get_server_message("settings_load_success", lang=current_lang))
            else:
                print(get_server_message("invalid_lang_setting", lang=settings.get("lang", "N/A")))
                current_lang = "en" # Fallback to English
        return True
    except json.JSONDecodeError as e:
        print(get_server_message("settings_json_decode_error", error=e))
        current_lang = "en"
        return False
    except Exception as e:
        print(get_server_message("settings_load_unexpected_error", error=e))
        current_lang = "en"
        return False

def save_settings(lang):
    """
    Saves the current language setting to the settings.json file.
    """
    global current_lang
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump({"lang": lang}, f, indent=4)
        current_lang = lang
        print(get_server_message("lang_setting_updated", lang=lang))
        return True
    except Exception as e:
        print(get_server_message("error_processing_set_settings", error=e))
        return False

def determine_email_spam_status(email_data, current_spam_settings):
    """
    Determines if an email is spam based on email_data and the processed spam configuration.
    Returns True if it's spam, False otherwise.
    """
    # Get spam filter criteria from current_spam_settings, with fallbacks
    score_limit = current_spam_settings.get("score_limit", 5) 
    whitelist_emails = current_spam_settings.get("whitelist_emails", set())
    whitelist_domains = current_spam_settings.get("whitelist_domains", set())
    blacklist_emails = current_spam_settings.get("blacklist_emails", set())
    blacklist_domains = current_spam_settings.get("blacklist_domains", set())
    whitelist_words = current_spam_settings.get("whitelist_words", set())
    blacklist_words = current_spam_settings.get("blacklist_words", set())

    # Extract sender and subject from email_data, converting to lowercase for case-insensitive comparison
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

    # Priority 1: Whitelists from spam_settings (highest priority)
    # 1a. By sender (email/domain)
    if (sender_email_lower and sender_email_lower in whitelist_emails) or \
       (sender_domain and sender_domain in whitelist_domains):
        return False
    # 1b. By keywords in the subject
    if any(word in subject_lower for word in whitelist_words):
        return False

    # Priority 2: Blacklists from spam_settings
    # 2a. By sender (email/domain)
    if (sender_email_lower and sender_email_lower in blacklist_emails) or \
       (sender_domain and sender_domain in blacklist_domains):
        return True
    # 2b. By keywords in the subject
    if any(word in subject_lower for word in blacklist_words):
        return True

    # Priority 3: Pre-existing fields in metadata (spam_filter_whitelist has priority over spam_filter)
    if email_data.get('spam_filter_whitelist', 'no').lower() == 'yes': return False
    if email_data.get('spam_filter', 'no').lower() == 'yes': return True
        
    # Priority 4: Spam score
    current_spam_score_raw = email_data.get('spam_score')
    if current_spam_score_raw is not None:
        try:
            if float(current_spam_score_raw) > score_limit:
                return True
        except (ValueError, TypeError):
            print(get_server_message("invalid_score_value", value=current_spam_score_raw))
            pass # Continue to default
            
    # Default: not spam
    return False

# --- HTTP Request Handler Class ---

class RequestHandler(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler. Extends BaseHTTPRequestHandler to
    serve static files, list email metadata, and manage viewing,
    reading, and downloading of .eml files.
    """

    def log_message(self, format, *args):
        """
        Overrides the default log_message to suppress HTTP access logs,
        keeping server logs cleaner.
        """
        return

    def do_GET(self):
        """
        Handles all incoming HTTP GET requests.
        Parses the requested URL and routes the request to the appropriate handler function.
        """
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)

        print(get_server_message("handling_get_request", path=path))

        # Route requests based on the path
        if path == '/' or path == '/index.html':
            self.serve_static_file('index.html')
        elif path == '/list-eml':
            self.list_eml_files_from_metadata(query_params)
        elif path.startswith('/read-eml'):
            self.read_eml_file()
        elif path.startswith('/download-eml'):
            self.download_eml_file()
        elif path.startswith('/view-html-eml'):
            self.view_html_eml_file()
        elif path == '/get-settings': # New endpoint to get language settings
            self.send_settings()
        else:
            print(get_server_message("resource_not_found", path=path))
            self.send_error(404, get_server_message("resource_not_found", path=""))

    def do_POST(self):
        """
        Handles all incoming HTTP POST requests.
        Used for updating settings.
        """
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/set-settings':
            self.set_settings()
        else:
            self.send_error(404, get_server_message("resource_not_found", path=""))

    def serve_static_file(self, filename):
        """
        Serves a static file from the local filesystem.
        Determines the appropriate Content-Type based on the file extension.
        """
        file_path_to_serve = os.path.join(SCRIPT_DIR, filename)
        print(get_server_message("serving_static_file", file=file_path_to_serve))
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
            print(get_server_message("static_file_served_success", file=filename, content_type=content_type))

        except FileNotFoundError:
            print(get_server_message("static_file_not_found", file=file_path_to_serve))
            self.send_error(404, get_server_message("static_file_not_found", file=""))
        except Exception as e:
            print(get_server_message("static_file_server_error", file=filename, error=e))
            self.send_error(500, get_server_message("static_file_server_error", file="", error=""))

    def list_eml_files_from_metadata(self, query_params):
        """
        Loads and sends metadata for all emails in JSON format.
        This function is used by the frontend to populate the main table.
        """
        global emails_metadata, spam_settings
        print(get_server_message("listing_eml_files"))
        load_metadata()

        processed_emails = []
        if emails_metadata and 'emails' in emails_metadata:
            for email_data in emails_metadata['emails']:
                current_settings_to_use = spam_settings if spam_settings is not None else _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)
                email_data['is_spam'] = determine_email_spam_status(email_data, current_settings_to_use)
                processed_emails.append(email_data)
        else:
            print(get_server_message("no_email_metadata_found"))

        response_data = {
            'emails': processed_emails,
            'total_emails': emails_metadata.get('total_emails', 0),
            'page': 1,
            'limit': emails_metadata.get('total_emails', 0)
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_content = json.dumps(response_data, indent=4)
        self.wfile.write(response_content.encode('utf-8'))
        print(get_server_message("sent_email_metadata_entries", count=len(processed_emails)))

    def read_eml_file(self):
        """
        Reads the content of an .eml file specified by the 'path' parameter in the URL
        and sends it as plain text in the HTTP response.
        """
        full_path = self.get_path_from_query()
        print(get_server_message("reading_eml_file", file=full_path))
        if not full_path:
            print(get_server_message("invalid_or_missing_path_read"))
            self.send_error(400, get_server_message("invalid_or_missing_path_read", file=""))
            return

        if not os.path.exists(full_path):
            print(get_server_message("file_not_found_read", file=full_path))
            self.send_error(404, get_server_message("file_not_found_read", file=os.path.basename(full_path)))
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.wfile.write(content.encode('utf-8')) 
            print(get_server_message("read_file_success", file=os.path.basename(full_path)))
        except Exception as e:
            print(get_server_message("read_file_server_error", file=full_path, error=e))
            self.send_error(500, get_server_message("read_file_server_error", file="", error=""))

    def download_eml_file(self):
        """
        Allows downloading an .eml file specified by the 'path' parameter in the URL.
        Sets the Content-Disposition header to force the browser to download the file.
        """
        full_path = self.get_path_from_query()
        print(get_server_message("downloading_eml_file", file=full_path))
        if not full_path:
            print(get_server_message("invalid_or_missing_path_download"))
            self.send_error(400, get_server_message("invalid_or_missing_path_download", file=""))
            return

        if not os.path.exists(full_path):
            print(get_server_message("file_not_found_download", file=full_path))
            self.send_error(404, get_server_message("file_not_found_download", file=os.path.basename(full_path)))
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream') 
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(full_path)}"')
        self.end_headers()
        try:
            with open(full_path, 'rb') as f:
                self.wfile.write(f.read())
            print(get_server_message("download_file_success", file=os.path.basename(full_path)))
        except Exception as e:
            print(get_server_message("download_file_server_error", file=full_path, error=e))
            self.send_error(500, get_server_message("download_file_server_error", file="", error=""))

    def send_error_page_for_view_html(self, code, title_key, message_content_html):
        """Helper to send a custom HTML error page for view_html_eml_file."""
        global current_lang
        error_html = f"""
        <!DOCTYPE html>
        <html lang="{current_lang}">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{get_server_message(title_key)}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; text-align: center; }}
                h1 {{ color: #e74c3c; }}
            </style>
        </head>
        <body>
            <h1>{get_server_message(title_key)}</h1>
            <p>{message_content_html}</p>
        </body>
        </html>
        """
        self.send_response(code)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(error_html.encode('utf-8'))

    def view_html_eml_file(self):
        """
        Generates an HTML preview of an .eml file.
        Extracts HTML or plain text content from the email and embeds it in a basic HTML structure.
        Implements spam detection logic and displays 'To' and 'CC' fields.
        """
        global spam_settings, current_lang

        # Extract 'path' parameter from the URL query
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # This is the path as sent by the client, and as potentially stored in metadata.json
        path_from_client_metadata = None
        if 'path' in query_params and query_params['path']:
            path_from_client_metadata = unquote(query_params['path'][0])

        print(get_server_message("viewing_html_eml_file", path=path_from_client_metadata))

        if not path_from_client_metadata:
            print(get_server_message("no_valid_path_html_view"))
            self.send_error(400, get_server_message("no_valid_path_html_view"))
            return

        # --- Determine the actual relative path for file system access ---
        # This part adjusts the path if it incorrectly starts with "emails/" or "emails\"
        # due to how it might be stored in metadata.json (e.g., relative to USER_DATA_DIR).
        normalized_path_from_client = path_from_client_metadata.replace('\\', '/')
        path_segments = normalized_path_from_client.split('/')
        
        rel_path_for_filesystem = path_from_client_metadata # Default
        if len(path_segments) > 1 and path_segments[0].lower() == 'emails':
            rel_path_for_filesystem = '/'.join(path_segments[1:])
            print(f"INFO: Path adjustment for filesystem access in view_html_eml_file: original '{path_from_client_metadata}', adjusted to '{rel_path_for_filesystem}'")

        # Construct the full path for file system operations
        base_dir_emails = CORREOS_BASE_DIR
        normalized_rel_path_for_fs_join = os.path.normpath(rel_path_for_filesystem)
        full_path = os.path.join(base_dir_emails, normalized_rel_path_for_fs_join)
        # --- End path adjustment for file system ---

        if not os.path.realpath(full_path).startswith(os.path.realpath(base_dir_emails)):
            print(get_server_message("security_alert_traversal", path=full_path))
            self.send_error(403, get_server_message("security_alert_traversal", path=full_path))
            return

        if not os.path.exists(full_path):
            print(get_server_message("eml_file_not_found_html_view", file=full_path))
            self.send_error_page_for_view_html(404, 
                                               "error_page_email_not_found_title",
                                               get_server_message("error_page_email_not_found_message1", path=path_from_client_metadata) + "<br>" +
                                               get_server_message("error_page_email_not_found_message2") + 
                                               f"<br><small>Attempted filesystem path: {full_path}</small>")
            return

        if not load_metadata():
            print(get_server_message("metadata_loading_failed_html_view"))
            self.send_error_page_for_view_html(500,
                                               "error_page_metadata_title",
                                               get_server_message("error_page_metadata_message"))
            return

        # Find the specific email's metadata
        email_metadata_item = None
        normalized_lookup_path = path_from_client_metadata.replace('\\', '/') 
        for email_entry in emails_metadata.get('emails', []):
            normalized_metadata_path = email_entry.get('path', '').replace('\\', '/')
            if normalized_metadata_path == normalized_lookup_path:
                email_metadata_item = email_entry
                break

        if not email_metadata_item:
            print(get_server_message("email_metadata_not_found_html_view", path=path_from_client_metadata))
            self.send_error_page_for_view_html(404,
                                               "error_page_email_not_found_title",
                                               get_server_message("error_page_email_not_found_message1", path=path_from_client_metadata) + "<br>" +
                                               get_server_message("error_page_email_not_found_message2"))
            return

        # Extract email headers and details from metadata
        subject_header = email_metadata_item.get('subject', 'No Subject')
        from_header = email_metadata_item.get('sender', 'Unknown Sender')
        account_recipient_header = email_metadata_item.get('recipient', 'Unknown Account')
        to_recipients = email_metadata_item.get('to', [])
        cc_recipients = email_metadata_item.get('cc', [])
        date_str = email_metadata_item.get('date', 'Unknown Date')
        time_str = email_metadata_item.get('time', 'Unknown Time')
        formatted_date_time = f"{date_str.replace('-', '/') if date_str and date_str != 'Unknown Date' else 'Unknown Date'} {time_str.replace('-', ':') if time_str and time_str != 'Unknown Time' else 'Unknown Time'}"
        
        # Determine if the email is spam
        current_settings_to_use = spam_settings if spam_settings is not None else _process_spam_config(DEFAULT_SPAM_SETTINGS, DEFAULT_SPAM_SETTINGS)
        is_spam = determine_email_spam_status(email_metadata_item, current_settings_to_use)
        spam_score_for_modal = email_metadata_item.get('spam_score') 

        html_content = None
        text_content = None
        charset = 'utf-8' # Default charset

        try:
            with open(full_path, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)

            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = part.get('Content-Disposition')
                # Skip attachments
                if cdisp and cdisp.startswith('attachment'):
                    continue
                # Try to get HTML content
                if ctype == 'text/html':
                    try:
                        charset = part.get_content_charset() or charset
                        html_content = part.get_payload(decode=True).decode(charset, errors='replace')
                        print(get_server_message("extracted_html_content", file=os.path.basename(full_path)))
                        break # Prefer HTML content
                    except Exception as e:
                        print(get_server_message("error_decoding_html_content", file=os.path.basename(full_path), error=e))
                        html_content = "<p>Error decoding HTML content.</p>"
                # Try to get plain text content if HTML is not found or if it's the first text part
                if ctype == 'text/plain' and text_content is None:
                    try:
                        charset = part.get_content_charset() or charset
                        text_content = part.get_payload(decode=True).decode(charset, errors='replace')
                        print(get_server_message("extracted_plain_text_content", file=os.path.basename(full_path)))
                    except Exception as e:
                        print(get_server_message("error_decoding_plain_text_content", file=os.path.basename(full_path), error=e))
                        text_content = "Error decoding plain text content."

        except Exception as e:
            # General error parsing the .eml file
            print(get_server_message("critical_error_parsing_eml", file=full_path, error=e))
            html_content = None
            text_content = "Critical error reading email content. Please check .eml file integrity."

        download_url = f"/download-eml?path={query_params['path'][0]}"

        # Construct the final HTML page for the preview
        final_html_content = f"""
<!DOCTYPE html>
<html lang="{current_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Preview: {subject_header}</title>
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
                {get_server_message('preview_simplified_message')}
            </div>
            <a id="downloadPreviewBtn" href="{download_url}" class="download-button-header" download>{get_server_message('preview_download_button')}</a>
        </div>
        {
            f'<div class="spam-warning-message">{get_server_message("preview_spam_warning")}</div>'
            if is_spam else ''
        }
        <div class="scrollable-email-content">
            <div class="email-details-preview">
                <div class="left-details">
                    <div class="detail-pair">
                        <strong>{get_server_message('preview_date_time')}</strong> <span class="detail-value">{formatted_date_time}</span>
                    </div>
                    <div class="detail-pair">
                        <strong>{get_server_message('preview_from')}</strong> <span class="detail-value">{from_header}</span>
                    </div>
                    {
                        '<div class="detail-pair">'
                        f'<strong>{get_server_message("preview_to")}</strong> <span class="detail-value">' + (', '.join(to_recipients) if to_recipients else 'N/A') + '</span>'
                        '</div>'
                    }
                    {
                        '<div class="detail-pair">'
                        f'<strong>{get_server_message("preview_cc")}</strong> <span class="detail-value">' + (', '.join(cc_recipients) if cc_recipients else 'N/A') + '</span>'
                        '</div>'
                    }
                    <div class="detail-pair">
                        <strong>{get_server_message('preview_subject')}</strong> <span class="detail-value">{subject_header}</span>
                    </div>
                </div>
                <div class="right-details">
                    <div class="detail-pair">
                        <strong>{get_server_message('preview_account')}</strong> <span class="detail-value">{account_recipient_header}</span>
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
            final_html_content += f"<p>{get_server_message('preview_no_content')}</p>"

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
                {get_server_message('preview_modal_security_alert')}<br>{get_server_message('preview_modal_spam_marked')}<br>
                {get_server_message('preview_modal_spam_score')} {spam_score_for_modal if spam_score_for_modal is not None else 'N/A'}<br>
                {get_server_message('preview_modal_download_malicious_warning')}<br>{get_server_message('preview_modal_continue_risk')}
            </p>
            <div class="modal-buttons">
                <button id="previewConfirmDownloadBtn">{get_server_message('preview_modal_download_anyway')}</button>
                <button id="previewCancelDownloadBtn">{get_server_message('preview_modal_cancel')}</button>
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
                    console.log('{get_server_message("console_displaying_spam_warning")} for download in preview.');
                }});
                confirmDownloadBtn.addEventListener('click', function() {{
                    spamModal.style.display = 'none'; 
                    window.location.href = downloadBtn.href; 
                    console.log('{get_server_message("console_spam_download_confirmed")}');
                }});
                cancelDownloadBtn.addEventListener('click', function() {{
                    spamModal.style.display = 'none'; 
                    console.log('{get_server_message("console_spam_download_cancelled")}');
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

    def send_settings(self):
        """
        Sends the current language settings to the client.
        """
        global current_lang
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_content = json.dumps({"lang": current_lang})
        self.wfile.write(response_content.encode('utf-8'))
        print(get_server_message("sent_settings", lang=current_lang))

    def set_settings(self):
        """
        Receives and saves language settings from the client.
        """
        global current_lang
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            settings_data = json.loads(post_data.decode('utf-8'))
            new_lang = settings_data.get('lang')
            print(get_server_message("received_set_settings_request", lang=new_lang))
            if new_lang and new_lang in ["en", "es"]:
                if save_settings(new_lang):
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "success", "lang": new_lang}).encode('utf-8'))
                else:
                    self.send_error(500, get_server_message("error_processing_set_settings", error="Failed to save settings"))
            else:
                self.send_error(400, get_server_message("invalid_lang_setting", lang=new_lang))
        except json.JSONDecodeError as e:
            print(get_server_message("invalid_json_set_settings", error=e))
            self.send_error(400, get_server_message("invalid_json_set_settings", error=""))
        except Exception as e:
            print(get_server_message("error_processing_set_settings", error=e))
            self.send_error(500, get_server_message("error_processing_set_settings", error=""))

    def get_path_from_query(self):
        """
        Extracts and validates the 'path' parameter from the URL query string.
        Implements a security measure to prevent Directory Traversal attacks,
        ensuring the requested path is within the allowed base directory.
        Returns the full, validated file path, or None if invalid or absent.
        """
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        path_from_query = None
        if 'path' in query_params and query_params['path']:
            path_from_query = unquote(query_params['path'][0]) 

        if not path_from_query:
            print(get_server_message("path_missing_or_empty"))
            return None

        # Adjust path if it incorrectly starts with "emails/" or "emails\"
        # This is to compensate for metadata paths that might be relative to USER_DATA_DIR
        # instead of CORREOS_BASE_DIR.
        normalized_path_from_query = path_from_query.replace('\\', '/')
        path_segments = normalized_path_from_query.split('/')
        
        actual_rel_path = path_from_query # Default to original
        if len(path_segments) > 1 and path_segments[0].lower() == 'emails':
            actual_rel_path = '/'.join(path_segments[1:])
            print(f"INFO: Path adjustment in get_path_from_query: original '{path_from_query}', adjusted to '{actual_rel_path}'")

        base_dir_emails = CORREOS_BASE_DIR
        # Use actual_rel_path for joining
        full_path = os.path.normpath(os.path.join(base_dir_emails, actual_rel_path))

        # Security check: ensure the resolved path is within the base email directory
        if not os.path.realpath(full_path).startswith(os.path.realpath(base_dir_emails)):
            print(get_server_message("security_alert_traversal", path=full_path))
            return None
        print(get_server_message("path_validation_success", path=full_path))
        return full_path

# --- Main Script Execution Block ---

if __name__ == '__main__':
    # Load initial data and settings when the server starts
    print(get_server_message("server_starting"))
    load_settings() # Load language settings first
    load_metadata()  
    load_spam_settings() 

    # Server configuration
    server_address = ('0.0.0.0', 8000)
    server = HTTPServer(server_address, RequestHandler)

    print(get_server_message("server_listening", ip=server_address[0], port=server_address[1]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(get_server_message("keyboard_interrupt"))
        server.shutdown() 
    except Exception as e:
        print(get_server_message("server_unexpected_error", error=e))
        pass
