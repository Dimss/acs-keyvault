# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import sys
import os
import json
import logging
import base64
import requests
from typing import List
from urllib.parse import urlparse
# from adal import AuthenticationContext
# # from azure.keyvault import KeyVaultClient
# from azure.identity import DefaultAzureCredential
# from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient, SecretProperties
from azure.keyvault.certificates import CertificateClient, CertificateProperties
from azure.identity import ClientSecretCredential

from msrestazure.azure_active_directory import AdalAuthentication, MSIAuthentication
from kubernetes import client, config
from OpenSSL import crypto
from config import conf

logging.basicConfig(level=logging.INFO,
                    format='|%(asctime)s|%(levelname)-5s|%(process)d|%(thread)d|%(name)s|%(message)s')

_logger = logging.getLogger('keyvault-agent')


# AZURE_AUTHORITY_SERVER = os.getenv('AZURE_AUTHORITY_SERVER', 'https://login.microsoftonline.com/')
# VAULT_RESOURCE_NAME = os.getenv('VAULT_RESOURCE_NAME', 'https://vault.azure.net')
# VAULT_BASE_URL = os.getenv('VAULT_BASE_URL')

class AcsKeyVaultClient(object):
    def __init__(self, vault_base_url: str, use_msi_auth: bool = True, service_principal_file_path: str = None):
        self._vault_base_url = vault_base_url
        self._use_msi = use_msi_auth
        self._service_principal_file_path = service_principal_file_path
        self.vault_secret_client = self._get_vault_secret_client()
        self.vault_certs_client = self._get_vault_certs_client()

    def msi_auth(self):
        pass

    def _get_vault_secret_client(self) -> SecretClient:
        if self._use_msi:
            return None  # return msi auth
        return SecretClient(**self._get_client_credentials())

    def _get_vault_certs_client(self) -> CertificateClient:
        return CertificateClient(**self._get_client_credentials())

    def _get_client_credentials(self) -> dict:
        try:
            return {"vault_url": self._vault_base_url, "credential": ClientSecretCredential(**self._parse_sp_file())}
        except Exception as ex:
            raise Exception(f"Error during creating client credentials: {ex}")

    def _parse_sp_file(self) -> dict:
        _logger.info(f'Parsing Service Principle file from: {self._service_principal_file_path}')
        if not os.path.isfile(self._service_principal_file_path):
            raise Exception(f"Service Principle file doesn't exist: {self._service_principal_file_path}")

        with open(self._service_principal_file_path, 'r') as sp_file:
            sp_data = json.load(sp_file)
            # retrieve the relevant values used to authenticate with Key Vault
            return {
                "tenant_id":     self._get_tenant_id(sp_data['tenantId']),
                "client_id":     sp_data['aadClientId'],
                "client_secret": sp_data['aadClientSecret']
            }

    def _get_tenant_id(self, tenant_id_from_config):
        if os.getenv('AUTO_DETECT_AAD_TENANT', 'false').lower() != 'true':
            _logger.info(
                    f'AAD tenant auto detection turned off. Using tenant id {tenant_id_from_config} from cloud config')
            return tenant_id_from_config

        # if we are unable to auto detect tenant id for any reason, we will use the one from config
        try:

            _logger.info('AAD tenant auto detection turned on. Detecting tenant id for %s', self._vault_base_url)
            # Send request pointing to any key to trigger a 401
            URL = '{}/keys/somekeyname/1?api-version=2018-02-14'.format(self._vault_base_url)
            _logger.info('Sending challenge request to %s', URL)
            response = requests.get(url=URL)
            if response.status_code == 401:
                # If status code == HTTP 401, then parse the WWW-Authenticate header to retrieve 'authorization' value
                # Bearer authorization="https://login.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47", resource=".."
                challenge = response.headers['WWW-authenticate'].lower()
                challenge_data = challenge.replace('bearer ', '').split(',')
                for kvp in challenge_data:
                    keyvalue = kvp.strip().split('=')
                    if len(keyvalue) == 2 and keyvalue[0] == 'authorization':
                        authority = keyvalue[1].replace('"', '')
                        tenant_id = urlparse(authority).path.replace('/', '')
                        _logger.info('Successfully auto detected tenant id : %s', tenant_id)
                        return tenant_id

                # if we cannot find in the for loop default the value and log
                _logger.error(
                        'Unable to find the tenant id from the received challenge [%s]. Using tenant id from config',
                        challenge)

            # if conditions are not met return the default tenant_id_from_config from cloud config file
            _logger.info(
                    'Unable to receive a challenge to auto detect AAD tenant. Received status code %d. Expected status code : 401. Using the config default %s',
                    response.status_code, tenant_id_from_config)
        except:
            _logger.error('Exception occured while trying to auto detect AAD tenant. Using the config default %s',
                          tenant_id_from_config)
        return tenant_id_from_config


class AcsKeyVaultAgent(AcsKeyVaultClient):
    """
    A Key Vault agent that reads secrets from Key Vault and stores them in a folder
    """

    def __init__(self, vault_base_url: str,
                 secrets_folder: str,
                 use_msi_auth: bool = True,
                 service_principal_file_path: str = None):

        super().__init__(vault_base_url, use_msi_auth, service_principal_file_path)

        self._secrets_folder = secrets_folder
        self._secrets_output_folder = self.get_secrets_output_folder()
        self._certs_output_folder = ""
        self._keys_output_folder = ""
        self._cert_keys_output_folder = ""
        self._api_instance = ""
        self._secrets_list = ""
        self._secrets_namespace = ""

    def get_secrets_output_folder(self):
        return os.path.join(self._secrets_folder, "secrets")

    def _get_kubernetes_api_instance(self):
        if self._api_instance is None:
            config.load_incluster_config()
            client.configuration.assert_hostname = False
            self._api_instance = client.CoreV1Api()

        return self._api_instance

    def _get_kubernetes_secrets_list(self):
        if self._secrets_list is None:
            api_instance = self._get_kubernetes_api_instance()
            api_response = api_instance.list_namespaced_secret(namespace=self._secrets_namespace)

            secret_name_list = []
            should_continue = True

            while should_continue is True:
                continue_value = api_response.metadata._continue
                secrets_list = api_response.items
                for item in secrets_list:
                    secret_name_list.append(item.metadata.name)

                if continue_value is not None:
                    api_response = api_instance.list_namespaced_secret(namespace=self._secrets_namespace,
                                                                       _continue=continue_value)
                else:
                    should_continue = False

            self._secrets_list = secret_name_list

        return self._secrets_list

    def _create_kubernetes_secret_objects(self, key, secret_value, secret_type):
        key = key.lower()
        api_instance = self._get_kubernetes_api_instance()
        secret = client.V1Secret()

        secret.metadata = client.V1ObjectMeta(name=key)
        secret.type = secret_type

        if secret.type == 'kubernetes.io/tls':
            _logger.info('Extracting private key and certificate.')
            p12 = crypto.load_pkcs12(base64.decodestring(secret_value))
            ca_certs = ()
            if os.getenv('DOWNLOAD_CA_CERTIFICATES', 'true').lower() == "true":
                ca_certs = (p12.get_ca_certificates() or ())
                certs = (p12.get_certificate(),) + ca_certs
            else:
                certs = (p12.get_certificate(),)
            privateKey = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
            certString = ""
            for cert in certs:
                certString += crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            secret.data = {'tls.crt': base64.encodestring(certString), 'tls.key': base64.encodestring(privateKey)}
            if ca_certs:
                ca_certs_string = ""
                for cert in ca_certs:
                    ca_certs_string += crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                secret.data.update({'ca.crt': base64.encodestring(ca_certs_string)})

        else:
            secretDataKey = key.upper() + "_SECRETS_DATA_KEY"
            secret_data_key = os.getenv(secretDataKey, 'secret')
            secret.data = {secret_data_key: base64.b64encode(bytes(secret_value))}

        secrets_list = self._get_kubernetes_secrets_list()

        _logger.info('Creating or updating Kubernetes Secret object: %s', key)
        try:
            if key in secrets_list:
                api_instance.patch_namespaced_secret(name=key, namespace=self._secrets_namespace, body=secret)
            else:
                api_instance.create_namespaced_secret(namespace=self._secrets_namespace, body=secret)
        except:
            _logger.exception("Failed to create or update Kubernetes Secret")

    def grab_secrets_kubernetes_objects(self):
        """
        Gets secrets from KeyVault and creates them as Kubernetes secrets objects
        """
        vault_base_url = os.getenv('VAULT_BASE_URL')
        secrets_keys = os.getenv('SECRETS_KEYS')
        self._secrets_namespace = os.getenv('SECRETS_NAMESPACE', 'default')

        # client = self._get_client()
        _logger.info('Using vault: %s', self._vault_base_url)

        # Retrieving all secrets from Key Vault if specified by user
        if secrets_keys is None:
            _logger.info('Retrieving all secrets from Key Vault.')

            all_secrets = list(client.get_secrets(self._vault_base_url))
            secrets_keys = ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

        if secrets_keys is not None:
            for key_info in filter(None, secrets_keys.split(';')):
                key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
                _logger.info('Retrieving secret name:%s with version: %s output certFileName: %s keyFileName: %s',
                             key_name, key_version, cert_filename, key_filename)
                secret = client.get_secret(self._vault_base_url, key_name, key_version)

                secretTypeEnvKey = key_name.upper() + "_SECRET_TYPE"
                secret_type = os.getenv(secretTypeEnvKey, os.getenv("SECRETS_TYPE", 'Opaque'))
                if secret_type == 'kubernetes.io/tls':
                    if secret.kid is not None:
                        _logger.info('Secret is backing certificate.')
                        if secret.content_type == 'application/x-pkcs12':
                            self._create_kubernetes_secret_objects(key_name, secret.value, secret_type)
                        else:
                            _logger.error('Secret is not in pkcs12 format')
                            sys.exit(1)
                    elif (key_name != cert_filename):
                        _logger.error('Cert filename provided for secret %s not backing a certificate.', key_name)
                        sys.exit(('Error: Cert filename provided for secret {0} not backing a certificate.').format(
                                key_name))
                else:
                    self._create_kubernetes_secret_objects(key_name, secret.value, secret_type)

    def grab_secrets(self, secrets: str = None):
        # grab key vault secrets
        self._grab_key_vault_secrets()

    def _grab_key_vault_secrets(self, secrets: str = None):
        secrets = self._compose_secret_names()
        for key_info in filter(None, secrets.split(';')):
            key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
            if cert_filename:
                # secret backing certificate, continue to next secret, certificate handled in dedicated function
                continue
            _logger.info(f'Retrieving secret name:{key_name} with version: {key_version}')
            secret = self.vault_secret_client.get_secret(key_name, key_version)
            output_path = os.path.join(self._secrets_output_folder, key_name)
            _logger.info('Dumping secret value to: %s', output_path)
            with open(output_path, 'w') as f:
                f.write(self._dump_secret(secret))

    def _grab_key_vault_certificates(self, secrets: str = None):
        pass

    def _compose_certs_names(self, secrets_names: str = None) -> str:
        """
        :return: string of all certificates names divided by ;
        """
        if secrets_names is not None:
            return secrets_names
        all_secrets = list(self.vault_certs_client.list_properties_of_certificates())
        return ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

    def _compose_secret_names(self, certs_names: str = None) -> str:
        """
        :return: string of all secrets names divided by ;
        """
        if certs_names is not None:
            return certs_names
        all_secrets = list(self.vault_secret_client.list_properties_of_secrets())
        return ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

    def grab_keys(self, keys: str = None):
        if keys is None:
            _logger.info('Retrieving all keys from Key Vault')
            all_secrets = list(self.vault_key_client.list_properties_of_keys())
            keys = ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

        for key_info in filter(None, keys.split(';')):
            key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
            _logger.info(
                    f'Retrieving secret name:{key_name} with version: {key_version} '
                    f'output certFileName: {cert_filename} keyFileName: {key_filename}')

            key = self.vault_key_client.get_key(key_name, key_version)
            output_path = os.path.join(self._secrets_output_folder, key_name)
            _logger.info('Dumping secret value to: %s', output_path)
            with open(output_path, 'w') as f:
                f.write(self._dump_secret(key))

        x = 1

    # def grab_secrets(self):
    #     """
    #     Gets secrets from KeyVault and stores them in a folder
    #     """
    #     secrets_keys = os.getenv('SECRETS_KEYS')
    #     certs_keys = os.getenv('CERTS_KEYS')
    #     output_folder = self._secrets_folder
    #     self._secrets_output_folder = os.path.join(output_folder, "secrets")
    #     self._certs_output_folder = os.path.join(output_folder, "certs")
    #     self._keys_output_folder = os.path.join(output_folder, "keys")
    #     self._cert_keys_output_folder = os.path.join(output_folder, "certs_keys")
    #
    #     for folder in (self._secrets_output_folder, self._certs_output_folder, self._keys_output_folder,
    #                    self._cert_keys_output_folder):
    #         if not os.path.exists(folder):
    #             os.makedirs(folder)
    #
    #     secret_client = self._get_secrets_client()
    #     _logger.info('Using vault: %s', self._vault_base_url)
    #
    #     if certs_keys is not None:
    #         for key_info in filter(None, certs_keys.split(';')):
    #             # only cert_filename is needed, key_filename is ignored with _
    #             key_name, key_version, cert_filename, _ = self._split_keyinfo(key_info)
    #             _logger.info('Retrieving cert name:%s with version: %s output certFileName: %s', key_name, key_version,
    #                          cert_filename)
    #             cert = client.get_certificate(self._vault_base_url, key_name, key_version)
    #             output_path = os.path.join(self._certs_output_folder, cert_filename)
    #             _logger.info('Dumping cert value to: %s', output_path)
    #             with open(output_path, 'w') as cert_file:
    #                 cert_file.write(self._cert_to_pem(cert.cer))
    #
    def _dump_pfx(self, pfx, cert_filename, key_filename):
        p12 = crypto.load_pkcs12(base64.b64decode(pfx))
        pk = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        if os.getenv('DOWNLOAD_CA_CERTIFICATES', 'true').lower() == "true":
            certs = (p12.get_certificate(),) + (p12.get_ca_certificates() or ())
        else:
            certs = (p12.get_certificate(),)

        if cert_filename == key_filename:
            key_path = os.path.join(self._keys_output_folder, key_filename)
            cert_path = os.path.join(self._certs_output_folder, cert_filename)
        else:
            # write to certs_keys folder when cert_filename and key_filename specified
            key_path = os.path.join(self._cert_keys_output_folder, key_filename)
            cert_path = os.path.join(self._cert_keys_output_folder, cert_filename)

        _logger.info('Dumping key value to: %s', key_path)
        with open(key_path, 'w') as key_file:
            key_file.write(pk.decode("utf-8"))

        _logger.info('Dumping certs to: %s', cert_path)
        with open(cert_path, 'w') as cert_file:
            for cert in certs:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        x = 1

    @staticmethod
    def _dump_secret(secret):
        value = secret.value
        if secret.properties.tags is not None and 'file-encoding' in secret.properties.tags:
            encoding = secret.properties.tags['file-encoding']
            if encoding == 'base64':
                value = base64.b64decode(value).decode("utf-8")

        return value

    @staticmethod
    def _split_keyinfo(key_info):
        key_parts = key_info.strip().split(':')
        key_name = key_parts[0]
        key_version = None if len(key_parts) < 2 else key_parts[1]
        cert_filename = None if len(key_parts) < 3 else key_parts[2]

        # key_filename set to cert_filename when only cert_filename is given
        # key_filename default to key_name when cert and key filenames are not given
        key_filename = None if len(key_parts) < 4 else key_parts[3]

        return key_name, key_version, cert_filename, key_filename

    @staticmethod
    def _cert_to_pem(cert):
        encoded = base64.encodestring(cert)
        if isinstance(encoded, bytes):
            encoded = encoded.decode("utf-8")
        encoded = '-----BEGIN CERTIFICATE-----\n' + encoded + '-----END CERTIFICATE-----\n'

        return encoded


if __name__ == '__main__':
    _logger.info('Grabbing secrets from Key Vault')
    if os.getenv('CREATE_KUBERNETES_SECRETS', 'false').lower() == "true":
        AcsKeyVaultAgent(conf.VAULT_BASE_URL, conf.SECRETS_FOLDER).grab_secrets_kubernetes_objects()
    else:
        AcsKeyVaultAgent(conf.VAULT_BASE_URL, conf.SECRETS_FOLDER, conf.SERVICE_PRINCIPLE_FILE_PATH).grab_secrets()
    _logger.info('Done!')
