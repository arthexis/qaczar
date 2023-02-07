
Independent nodes add context before everything else is evaluated, for example:
NAME = `arthexis`

## [Zero-File](Zero-File)
Remove all contents from the target.

```python
with open(r'Products\Test-Report.md', 'w') as f: 
    f.write('')
```

### Platform Info
Using Python: `C:\Python311\python.exe`
Current Directory: `C:\Users\arthe\Desktop\qaczar\root`
Name: `arthexis`

## [Screenshot](Screenshot)
Use Python to take a screenshot of the active window.

```python
import pyautogui

screenshot = pyautogui.screenshot()
screenshot.save(r"Products\last-screenshot.png")
```

![Products/last-screenshot.png](Products/last-screenshot.png)

### Notes
This gets automatically copied to the target.

Example Input

## [Test-Sigils](Test-Sigils)
```python
array = 
array.append("Example Input")
print(array)
```
> Example Input
