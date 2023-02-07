Find a window by approximate name and bring it to the fore.

```python
from pywinauto.application import Application
app = Application().connect(title_re=r".*[WINDOW].*")
app.get_focus()
```
