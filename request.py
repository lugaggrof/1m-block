import requests
res = requests.get('http://test.gilgil.net')
print(res.data[:30])
