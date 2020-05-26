import unittest
import os
from typing import List, Dict
from .acs_keyvault_agent import AcsKeyVaultAgent, AcsKeyVaultClient
from azure.keyvault.secrets import SecretProperties
from azure.keyvault.certificates import CertificatePolicy
from dataclasses import dataclass
from config import conf
import uuid


@dataclass
class TestData:
    secrets: []
    certs: []


TEST_DATA = TestData(
        secrets=[
            {
                'name':  f'test-secret-{str(uuid.uuid4())}',
                'value': str(uuid.uuid4())
            },
            {
                'name':  f'test-secret-{str(uuid.uuid4())}',
                'value': str(uuid.uuid4())
            }
        ],
        certs=[
            {
                'name':   'test-cert-' + str(uuid.uuid4()),
                'policy': CertificatePolicy("Self", subject="CN=bedude.io")
            },
            {
                'name':   'test-cert-' + str(uuid.uuid4()),
                'policy': CertificatePolicy("Self", subject="CN=bedude.io")
            }
        ]

)


class AcsKeyVaultCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._create_test_certs_and_secrets()

    @classmethod
    def tearDownClass(cls):
        cls._delete_test_certs_and_secrets()

    @classmethod
    def _create_test_certs_and_secrets(cls):
        kvc = AcsKeyVaultClient(conf.VAULT_BASE_URL, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
        cert_poller = None
        # create test certificate
        for cert in TEST_DATA.certs:
            cert_poller = kvc.vault_certs_client.begin_create_certificate(cert['name'], cert['policy'])
        # wait for last certificate
        if cert_poller:
            cert_poller.wait()
        # create test secrets
        for secret in TEST_DATA.secrets:
            kvc.vault_secret_client.set_secret(secret['name'], secret['value'])

    @classmethod
    def _delete_test_certs_and_secrets(cls):
        kvc = AcsKeyVaultClient(conf.VAULT_BASE_URL, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
        # delete all test certificates
        for cert in list(kvc.vault_certs_client.list_properties_of_certificates()):
            kvc.vault_certs_client.begin_delete_certificate(cert.name)
        # delete all test secrets
        for secret in list(kvc.vault_secret_client.list_properties_of_secrets()):
            if secret.content_type == 'application/x-pkcs12':
                continue
            kvc.vault_secret_client.begin_delete_secret(secret.name)

    @staticmethod
    def _is_secret_found(secret_name: str, secrets_props_list: List[SecretProperties]) -> bool:
        for secret_prop in secrets_props_list:
            if secret_prop.name == secret_name:
                return True
        return False

    def test_auth(self):
        kvc = AcsKeyVaultClient(conf.VAULT_BASE_URL, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
        secret_client = kvc._get_vault_secret_client()
        secret_client.list_properties_of_secrets()
        self.assertTrue(
                self._is_secret_found(TEST_DATA.secrets[0]["name"], list(secret_client.list_properties_of_secrets())))

    def test_grab_single_secret(self):
        acs_agent = AcsKeyVaultAgent(conf.VAULT_BASE_URL, conf.SECRETS_FOLDER, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
        acs_agent.grab_secrets(TEST_DATA.secrets[0]["name"])
        # check if secret name match file name
        secret_file = os.path.join(acs_agent.get_secrets_output_folder(), TEST_DATA.secrets[0]["name"])
        self.assertTrue(os.path.isfile(secret_file), f"Expected secret file: {secret_file} wasn't found")
        # check secret content
        with open(secret_file, 'r') as f:
            secret_file_content = f.read()
        self.assertEqual(TEST_DATA.secrets[0]["value"], secret_file_content, f"The secret content is not equal")

    def test_grab_all_secrets(self):
        acs_agent = AcsKeyVaultAgent(conf.VAULT_BASE_URL, conf.SECRETS_FOLDER, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
        acs_agent.grab_secrets()
        for secret in TEST_DATA.secrets:
            # check if secret name match to file name
            secret_file = os.path.join(acs_agent.get_secrets_output_folder(), secret["name"])
            self.assertTrue(os.path.isfile(secret_file), f"Expected secret file: {secret_file} wasn't found")
            # check secret content
            with open(secret_file, 'r') as f:
                secret_file_content = f.read()
            self.assertEqual(secret["value"], secret_file_content, f"The secret content is not equal")

    # def test_grab_key(self):
    #     acs_agent = AcsKeyVaultAgent(conf.VAULT_BASE_URL, conf.SECRETS_FOLDER, False, conf.SERVICE_PRINCIPLE_FILE_PATH)
    #     acs_agent.grab_keys()


if __name__ == '__main__':
    unittest.main()
