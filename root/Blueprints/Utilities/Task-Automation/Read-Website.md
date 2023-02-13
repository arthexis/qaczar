Use BS4 to read all text from a website.

```python
from bs4 import BeautifulSoup
from urllib.request import urlopen

with urlopen(r"[URL]") as f:
    html = f.read().decode('utf-8')
soup = BeautifulSoup(html, 'html.parser')
with open(f"[TARGET]", 'w', encoding='utf-8') as f:
    f.write(soup.get_text())
```