# modules/screenshot.py

import os
import time
from datetime import datetime

def take_screenshot(domain, output_dir="output"):
    """Take screenshot of target website"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager

        os.makedirs(output_dir, exist_ok=True)

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-gpu")
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )

        url = f"https://{domain}"
        driver.get(url)
        time.sleep(3)

        filename = f"{output_dir}/screenshot_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        driver.save_screenshot(filename)
        title = driver.title
        current_url = driver.current_url
        driver.quit()

        return {
            "success": True,
            "filename": filename,
            "title": title,
            "final_url": current_url,
            "redirected": current_url != url
        }

    except Exception as e:
        return {"success": False, "error": str(e)}