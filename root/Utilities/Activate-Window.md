Find a window by approximate name and bring it to the fore.

```python
from pywinauto.application import Application
app = Application().connect(title_re=r".*[APP].*")
win = app.top_window()
win.set_focus()
print(win.title)
```
