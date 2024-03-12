import requests
import os

def get_proxies():
    url = 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all'
    response = requests.get(url)
    if response.status_code == 200:
        proxies = response.text.split('\r\n')
        return proxies
    else:
        print("Failed to fetch proxies.")
        return []

def save_proxies(proxies):
    with open('proxy.txt', 'w') as file:
        for proxy in proxies:
            file.write(proxy + '\n')

def clear_old_proxies():
    if os.path.exists('proxy.txt'):
        os.remove('proxy.txt')

def main():
    clear_old_proxies()
    proxies = get_proxies()
    save_proxies(proxies)
    print("Proxies have been successfully saved to proxy.txt")

if __name__ == "__main__":
    main()