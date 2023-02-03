# Extract text from an image using Tesseract OCR

import cv2
import pytesseract

import qaczar


def images_to_text(source_pngs: set, target_txt: str = None) -> None:
    results = []
    for source_png in source_pngs:
        print(f"Reading {source_png}")
        image = cv2.imread(source_png)
        result = pytesseract.image_to_string(image)
        results.append(result)
    text = "\n".join(results)
    if target_txt is None:
        print(text)
    else:
        print(f"Writing {target_txt}")
        with open(target_txt, "w") as f:
            f.write(text)


if __name__ == "__main__":
    source_pngs = qaczar.parse_argfiles("in", "png")
    target_txt = qaczar.parse_argfile("out", "txt") 
    images_to_text(source_pngs, target_txt)

