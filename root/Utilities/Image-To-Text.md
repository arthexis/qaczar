Use OCR (Tesseract) to extract text from an image.

```python
import cv2
import pytesseract
img = cv2.imread(r"[INPUT]")
text = pytesseract.image_to_string(img)
print(text)
```