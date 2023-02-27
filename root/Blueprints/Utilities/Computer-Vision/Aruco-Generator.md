```python
import cv2
import numpy as np
import cv2.aruco as aruco

size = int("[SIZE]" or 200)
marker_id = int("[MARKER_ID]" or 1)
aruco_dict = aruco.getPredefinedDictionary(aruco.DICT_4X4_50)
markers = np.zeros((size, size), dtype=np.uint8)
markers = aruco.drawMarker(dictionary, marker_id, size, markers, 1)
cv2.imwrite("[TARGET]", markers)
```