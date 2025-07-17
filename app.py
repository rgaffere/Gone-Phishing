from flask import Flask, render_template, request
from domain_check import is_suspicious_email
from content_check import predict_email_with_confidence

app = Flask(__name__)

# Define the route for the home page
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Define the route for the form submission
@app.route('/submit', methods=['POST'])
def submit():
    email_content = request.form.get('input1')
    sender_email = request.form.get('input2')

    # Perform domain check
    suspicious_domain, domain_reason = is_suspicious_email(sender_email)

    # Perform phishing detection using the email content
    result, confidence = predict_email_with_confidence(email_content)

    if suspicious_domain:
        domain_message = f"Domain check: {domain_reason}"
    else:
        domain_message = "Domain check: No issues found."

   # Ensure the confidence value is between 0 and 100
    confidence_percentage = round(confidence * 100, 2)

    # Check that confidence is within the expected range
    if confidence_percentage > 100:
        confidence_percentage = 100
    elif confidence_percentage < 0:
        confidence_percentage = 0

    return render_template('result.html',
                           result=result,
                           confidence = confidence_percentage,  # Convert confidence to percentage
                           additional_info=domain_message)

if __name__ == "__main__":
    app.run(debug=True)
