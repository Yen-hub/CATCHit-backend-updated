import joblib
from .model_url_scanner import predict_url

class URLScanner:
    def __init__(self):
        self.model = joblib.load('url_classifier.pkl')
        self.vectorizer = joblib.load('vectorizer.pkl')

    def scan_url(self, url):
        try:
            return predict_url(url, self.model, self.vectorizer)
        except Exception as e:
            raise Exception(f"Error scanning URL: {str(e)}")