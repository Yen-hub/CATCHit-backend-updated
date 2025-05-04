import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from app.model_url_scanner import URLTokenizer

def train_model():
    # Load and preprocess data
    df = pd.read_csv('malicious_phish.csv')
    df['type'] = df['type'].apply(lambda x: 1 if x != 'benign' else 0)

    # Initialize tokenizer and vectorizer
    tokenizer = URLTokenizer()
    vectorizer = TfidfVectorizer(tokenizer=tokenizer._tokenize)

    # Extract features
    X = vectorizer.fit_transform(df['url'])
    y = df['type']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)

    # Save model and vectorizer
    joblib.dump(model, 'url_classifier.pkl')
    joblib.dump(vectorizer, 'vectorizer.pkl')
    
    print("Model trained and saved successfully!")

if __name__ == "__main__":
    train_model()