import joblib
import pandas as pd

# Step 1: Load the model and vectorizer
rf_model = joblib.load('phishing_rf_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')

# Step 2: Define a function to predict whether an email is phishing or safe and get confidence
def predict_email_with_confidence(email_content):
    # Step 3: Transform the email using the loaded vectorizer
    email_tfidf = vectorizer.transform([email_content])
    
    # Step 4: Make a prediction and get probabilities
    probabilities = rf_model.predict_proba(email_tfidf)
    
    # Get the predicted class
    predicted_class = rf_model.predict(email_tfidf)[0]
    
    # Step 5: Map predicted class to readable format
    if predicted_class == 1:
        result = "Phishing Email"
        confidence = probabilities[0][1]  # Confidence for phishing
    else:
        result = "Safe Email"
        confidence = probabilities[0][0]  # Confidence for safe email
    
    return result, confidence
