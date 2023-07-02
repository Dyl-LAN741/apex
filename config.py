# coding: utf-8

# API session configuration
# for read yaml file
import yaml

# path to API key file
PATH = "./config.yml"

file = open(PATH, "r")
config = yaml.load(file)
file.close()

url = config["api_apex"]["url"]
id = config["api_apex"]["id"]
key = config["api_apex"]["key"]

def api_url():
    """Return API url for login session"""
    return url

def api_id():
    """Return API version for login session"""
    return id

def api_key():
    """Return API key for login session"""
    return key
