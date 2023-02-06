
# Test Webcam
This document tests various webcam functions and generates a report.

## [Webcam-Capture](Webcam-Capture)
This script takes a snaptshot using the webcam.

```python
import cv2, time
cap = cv2.VideoCapture(int("" or 0))
cap.set(cv2.CAP_PROP_FRAME_WIDTH, int("" or 1920))
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, int("" or 1080))
time.sleep(1)
ret, frame = cap.read()
cap.release()
assert frame is not None and frame.any(), "Cam busy or invalid."
cv2.imwrite(r"C:\Users\arthe\Desktop\qaczar\root\Products\last-web-capture.png" or "untitled-frame.png", frame)
```

![Products/last-web-capture.png](Products/last-web-capture.png)

### Cropping
We use smartcroppy to crop the image easily.
`smartcroppy --width 1100 --height 800 Products/last-web-capture.png C:\Users\arthe\Desktop\qaczar\root\Products\cropped-img.png`

![Products/cropped-img.png](Products/cropped-img.png)

## [Image-To-Text](Image-To-Text)
Use OCR (Tesseract) to extract text from an image.

```python
import cv2
import pytesseract
img = cv2.imread(r"Products/cropped-img.png")
text = pytesseract.image_to_string(img)
print(text)
```
