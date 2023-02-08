Highlight instances of a template found within a given image.

```python
import cv2
import numpy as np
from matplotlib import pyplot as plt

img_rgb = cv2.imread(r'[INPUT]')
img_gray = cv2.cvtColor(img_rgb, cv2.COLOR_BGR2GRAY)
template = cv2.imread(r'[TEMPLATE]', 0)
w, h = template.shape[::-1]

res = cv2.matchTemplate(img_gray,template,cv2.TM_CCOEFF_NORMED)
threshold = 0.8
loc = np.where( res >= threshold)
x1, y1, x2, y2 = 0, 0, 0, 0
for pt in zip(*loc[::-1]):
    x1, y1, x2, y2 = pt[0], pt[1], pt[0] + w, pt[1] + h
    cv2.rectangle(img_rgb, pt, (x2, y2), (0,0,255), 2)

cv2.imwrite(r'[TARGET]', img_rgb)
print(f"X1 = {x1}")
print(f"Y1 = {y1}")
print(f"X2 = {x2}")
print(f"Y2 = {y2}")
```