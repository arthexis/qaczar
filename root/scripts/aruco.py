import cv2
import numpy as np

for id in range(1, 7):
    # Create a blank image with a white background
    img = np.ones((200, 200, 3), dtype=np.uint8) * 255

    # Create the marker
    marker = cv2.aruco.drawDetectedMarkers(img, np.array([[[id]]]), borderColor=(0, 0, 0))[0]

    # Display the marker
    cv2.imshow(f"Marker ID: {id}", marker)
    cv2.waitKey(0)
    cv2.destroyAllWindows()



