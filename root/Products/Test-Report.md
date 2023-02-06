
Independent nodes add context before everything else is evaluated, for example:
NAME = `arthexis`

### Platform Info
Using Python: `C:\Python311\python.exe`
Current Directory: `C:\Users\arthe\Desktop\qaczar\root`
Name: `arthexis`

## [Screenshot](Screenshot)
Use Python to take a screenshot of the active window.

```python
import pyautogui

screenshot = pyautogui.screenshot()
screenshot.save(r"[TARGET.PATH]")
```

![Products/last-screenshot.png](Products/last-screenshot.png)

### Notes
This gets automatically copied to the target.

## [Test-Sigils](Test-Sigils)
```python
array = []
array.append("[INPUT]")
print(array[0])
```
> ## (Screenshot)
> Use Python to take a screenshot of the active window.
> ```python
> import pyautogui
> screenshot = pyautogui.screenshot()
> screenshot.save(r"C:\Users\arthe\Desktop\qaczar\root\Products\Test-Report.md")
> ```
