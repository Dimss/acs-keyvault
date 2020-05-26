import os, json
from configparser import ConfigParser

# Load configs file
config = ConfigParser(os.environ)
app_ini_file = 'dev.app.ini'
PROFILE = os.getenv('PROFILE', 'dev')
if PROFILE == 'prod':
    app_ini_file = 'prod.app.ini'
config.read("{current_dir}/{ini_file}".format(current_dir=os.path.dirname(__file__), ini_file=app_ini_file))

AZURE_AUTHORITY_SERVER = config.get('app', 'azure_authority_server')
VAULT_RESOURCE_NAME = config.get('app', 'vault_resource_name')
VAULT_BASE_URL = config.get('app', 'vault_url')
SECRETS_FOLDER = config.get('app', 'secrets_folder')
SERVICE_PRINCIPLE_FILE_PATH = config.get('app', 'service_principle_file_path')
SECRETS_KEYS = config.get('app', 'secrets_keys')
CERTS_KEYS = config.get('app', 'certs_keys')
