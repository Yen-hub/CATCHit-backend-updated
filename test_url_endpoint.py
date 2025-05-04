import requests
import json

def test_url_scan():
    url = "http://localhost:5000/scan/url"
    headers = {"Content-Type": "application/json"}
    data = {"url": "https://www.google.com"}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_url_scan()