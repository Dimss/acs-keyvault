import msal
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys import KeyClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential

client_id = "6adb0fed-5ee3-4042-9189-77efef84d6e9"
client_secret = "04d16eec-af16-4c67-9445-f3854b50268b"
authority = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47"
scope = "https://vault.azure.net/.default"

# app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
#
# # result = app.acquire_token_silent(scope, account=None)
#
# result = app.acquire_token_for_client(scopes=[scope])
#
# d = DefaultAzureCredential(result)
# print(result)


credential = ClientSecretCredential("72f988bf-86f1-41af-91ab-2d7cd011db47", client_id, client_secret)

conn_str = {"vault_url": "https://bedude-vault.vault.azure.net", "credential": credential}
client = SecretClient(**conn_str)
secret = client.get_secret("mysecret1")
print(secret.value)

client = KeyClient(**conn_str)
key = client.get_key("bedude-key")
print(key.key)

client = CertificateClient(**conn_str)
cert = client.get_certificate("bedude-cert")
print(cert.cer)
x = 1

# import os
# from azure.identity import DefaultAzureCredential, ClientSecretCredential, ChainedTokenCredential, \
#     ClientSecretCredential
# from azure.keyvault.secrets import SecretClient
#
# credential = DefaultAzureCredential()
#


from azure.common.credentials import ServicePrincipalCredentials
from msrestazure.azure_active_directory import AdalAuthentication, MSIAuthentication
from adal import AuthenticationContext
#
# VAULT_RESOURCE_NAME = 'https://vault.azure.net'
#
# # "tenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
# # "subscriptionId": "8700d3a3-3bb7-4fbe-a090-488a1ad04161",
# # "aadClientId": "6adb0fed-5ee3-4042-9189-77efef84d6e9",
#
#
# client_id = "6adb0fed-5ee3-4042-9189-77efef84d6e9"
# client_secret = "04d16eec-af16-4c67-9445-f3854b50268b"
# # authority = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47"
# # context = AuthenticationContext(authority)
# # credentials = AdalAuthentication(context.acquire_token_with_client_credentials, VAULT_RESOURCE_NAME, client_id,
# #                                  client_secret)
# credentials = ClientSecretCredential(
#         tenant_id="72f988bf-86f1-41af-91ab-2d7cd011db47",
#         client_id=client_id,
#         client_secret=client_secret,
#         )
#
# # c1 = ChainedTokenCredential(credentials)
# #
# # c = context.acquire_token_with_client_credentials(VAULT_RESOURCE_NAME, client_id, client_secret)
# #
# # credential = DefaultAzureCredential()
#
#
# x = 1
#
# # credentials = ClientSecretCredential(
# #         client_id="6adb0fed-5ee3-4042-9189-77efef84d6e9",
# #         secret="04d16eec-af16-4c67-9445-f3854b50268b",
# #         tenant="72f988bf-86f1-41af-91ab-2d7cd011db47"
# #         )
# #
# key_client = SecretClient("https://bedude-vautl.vault.azure.net", credentials)
# secret = key_client.get_secret("mysecret1")
# print(secret)
# x = 1
