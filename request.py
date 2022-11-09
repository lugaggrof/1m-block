import requests
URL = 'http://test.gilgil.net'
response = requests.get(URL)
print(response.status_code)
print(response.text[:35])

