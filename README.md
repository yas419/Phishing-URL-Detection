# 🛡️ Phishing URL Detection System

A simple yet powerful web application that identifies whether a URL is **legitimate** or a **phishing attempt** using a combination of **rule-based heuristics** and an optional **machine learning model**.

## 🚀 Try the App

**[Launch the Web App](https://yasurldetection.streamlit.app/)** 
*No installation needed – runs entirely in your browser!*

## 📌 Features

- ✅ **Dual Detection Methods**
  - Rule-based checks (domain structure, SSL, special characters, etc.)
  - Optional Machine Learning model (RandomForestClassifier)
- 🔍 **Detailed Analysis**
  - Comprehensive breakdown of suspicious patterns
  - Clear visualization of detection results
- 📈 **Smart Evaluation**
  - Confidence score with supporting evidence
  - Transparent reasoning for each decision
- ⚡ **Optimized Performance**
  - Fast processing times
  - Interactive web interface built with Streamlit

## 🧪 Sample URLs to Test

### 🔴 Phishing-like Examples
- `http://paypal.account.verify-login.com`
- `http://secure-appleid.apple.com.verify-login.tk`
- `http://bankofamerica.verify-security-alert.cf`
- `http://linkedin-connect-update.ml`

### 🟢 Legitimate Examples
- `https://www.google.com`
- `https://www.amazon.com`
- `https://www.linkedin.com`

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3 | Core programming language |
| Streamlit | Web application framework |
| scikit-learn | Machine learning functionality |
| tldextract | Domain parsing and analysis |
| joblib | Model serialization |

## 📁 How to Run Locally

```bash
# Clone the repository
git clone https://github.com/Jawaharparvez/Phishing-URL-Detection-System.git

# Navigate to project directory
cd Phishing-URL-Detection-System

# Install dependencies
pip install -r requirements.txt

# Launch the application
streamlit run app.py
```


---

## ✨ Author

Made with ❤️ by **Yaseen**
