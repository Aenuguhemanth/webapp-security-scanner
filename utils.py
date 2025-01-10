# utils.py
import requests
from bs4 import BeautifulSoup
import re
import shodan

# Function to make HTTP requests and handle timeouts
def make_request(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.exceptions.Timeout:
        print(f"Timeout error while connecting to {url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error while connecting to {url}: {e}")
        return None

# Function to discover forms on a page
def discover_forms(url):
    response = make_request(url)
    if response:
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        return forms
    return []

# Function to discover input fields
def discover_inputs(url):
    response = make_request(url)
    if response:
        soup = BeautifulSoup(response.text, "html.parser")
        inputs = soup.find_all("input")
        return inputs
    return []

# Function to check for open redirects
def check_open_redirect(url):
    redirect_payload = "http://example.com"
    response = make_request(url)
    if response and redirect_payload in response.url:
        return True
    return False
