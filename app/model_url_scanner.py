import re
from flask import jsonify
from sklearn.base import BaseEstimator, TransformerMixin

class URLTokenizer(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        return [self._tokenize(url) for url in X]
    
    def _tokenize(self, url):
        tokens = re.split('[/-]', url)
        return [token for token in tokens if token]

def predict_url(url, model, vectorizer):
    try:
        # Transform URL using the vectorizer
        url_features = vectorizer.transform([url])
        prediction = int(model.predict(url_features)[0])  # Convert to int for JSON serialization
        probabilities = model.predict_proba(url_features)[0]
        confidence = float(max(probabilities))  # Ensure float for JSON serialization
        is_malicious = bool(prediction == 1)  # Convert to bool for clarity
        classification = "Malicious" if is_malicious else "Benign"
        
        return {
            "url": str(url),  # Ensure string
            "classification": classification,
            "is_malicious": is_malicious,
            "confidence": confidence
        }
    except Exception as e:
        raise Exception(f"Error predicting URL: {str(e)}")