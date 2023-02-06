# Take a screenshot of the active window or URL

import qaczar


def webdriver_screenshot(source_url, target_png):
    # TODO: Screenshot is not being saved correctly
    from selenium.webdriver.chrome.options import Options
    from selenium import webdriver
    options = Options()
    if qaczar.parse_flags("headless"):
        options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)
    driver.get(source_url)
    print(f"Taking screenshot of {source_url} and saving to {target_png}")
    driver.save_screenshot(target_png)
    driver.quit()


def pyautogui_screenshot(target_png):
    import pyautogui
    screenshot = pyautogui.screenshot()
    screenshot.save(target_png)


if __name__ == "__main__":
    source_url = qaczar.parse_argfile("in", "url")
    target_png = qaczar.parse_argfile("out", "png")
    print(f"Taking screenshot of {source_url=} and saving to {target_png=}")

    if source_url is not None:
        webdriver_screenshot(source_url, target_png)
    else:
        pyautogui_screenshot(target_png)




