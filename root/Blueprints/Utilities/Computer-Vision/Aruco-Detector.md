See if this works better:
https://pyimagesearch.com/2020/12/21/detecting-aruco-markers-with-opencv-and-python/

Currently...

```python
import cv2
import cv2.aruco as aruco

# Load the image
img = cv2.imread('[INPUT]')

# Define the Aruco dictionary to be used
aruco_dict = aruco.getPredefinedDictionary(aruco.DICT_4X4_100)

# Detect the markers in the image
corners, ids, rejectedImgPoints = aruco.detectMarkers(img, aruco_dict)

# If any markers are detected, label them in the image
if len(corners) > 0:
    # Draw the detected markers and label them with their IDs
    img_with_markers = aruco.drawDetectedMarkers(img, corners, ids)
    for i in range(len(ids)):
        c = corners[i][0]
        cv2.putText(img_with_markers, str(ids[i][0]), (c[0], c[1]), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2, cv2.LINE_AA)
        
    # Show the image with the detected markers
    cv2.imshow('Image with Aruco markers', img_with_markers)
    cv2.waitKey(0)
else:
    print('No markers detected in the image')

```