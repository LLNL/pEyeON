import requests
import oidc_client

'''
flow

try auth against endpoint 
get auth token
specify tar/gz file
upload with auth header to endpoint
'''

DEFAULT_CONFIG_FILE = "pyproject.toml"

def get_api_upload_url() -> str:
    '''
    get the upload url from the pyproject.toml
    '''
    pass

def get_oauth_config() -> oidc_client.config.ClientProfile:
    '''
    get the OIDC profile from the pyproject.toml
    '''
    pass

def get_provider_config(oauth_profile: oidc_client.config.ClientProfile) -> oidc_client.discovery.ProviderConfig:
    '''
    get provider config
    '''
    pass

def login()->oidc_client.oauth.TokenResponse:
    '''
    login and get the token
    '''
    pass

def upload_file(file:str):
    '''
    upload the target file ; verify it's a tar file 
    '''
    pass
