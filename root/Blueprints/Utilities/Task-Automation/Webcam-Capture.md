This script takes a snaptshot using the webcam.

```python
import cv2, time
cap = cv2.VideoCapture(int("[WEBCAM]" or 0))
cap.set(cv2.CAP_PROP_FRAME_WIDTH, int("[WIDTH]" or 1920))
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, int("[HEIGHT]" or 1080))
time.sleep(1)
ret, frame = cap.read()
cap.release()
assert frame is not None and frame.any(), "Cam busy or invalid."
cv2.imwrite(r"[TARGET]", frame)
```