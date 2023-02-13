Ask the user for input and output that.

```python
import tkinter as tk 
from tkinter import messagebox 
root = tk.Tk() 
root.withdraw() 
answer = messagebox.askokcancel("QACZAR", "[PROMPT]") 
print(answer)
```