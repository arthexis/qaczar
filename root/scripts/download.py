# Download a file from the web

import requests
import qaczar


source_url, target_file = qaczar.parse_argfiles("url", "html")

print(f"Downloading {source_url}")
response = requests.get(source_url)
with open(target_file, "wb") as f:
    f.write(response.content)

