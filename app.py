import streamlit as st
from phishing_detector import SimplePhishingDetector  # We'll move the class to this file
import time

# Page config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# App title
st.title("🔍 Phishing URL Detector")
st.markdown("Enter any URL below to detect whether it’s a **phishing attempt** or **legitimate** using rule-based or ML analysis.")

# Input form
url = st.text_input("🔗 Enter a URL to scan", placeholder="e.g. http://example.com")

# Analyze button
if st.button("Analyze URL"):
    if url.strip() == "":
        st.warning("Please enter a valid URL.")
    else:
        with st.spinner("Analyzing..."):
            detector = SimplePhishingDetector()
            result = detector.analyze_url(url)
            time.sleep(1)  # Just for smoother loading

        st.subheader("🔎 Analysis Result")
        st.write(f"**URL:** {result['url']}")

        if result['is_phishing']:
            st.error("⚠️ This URL appears to be **PHISHING**")
            st.write(f"**Confidence:** {result['confidence']:.2f}")
            st.markdown("**Reason(s):**")
            for reason in result['reasons']:
                st.markdown(f"- {reason}")
        else:
            st.success("✅ This URL appears to be **SAFE**")
            st.write(f"**Confidence:** {1 - result['confidence']:.2f}")
            if result['reasons']:
                st.markdown("**Note:**")
                for reason in result['reasons']:
                    st.markdown(f"- {reason}")

# Footer
st.markdown("---")
st.markdown("Made with ❤️ using Streamlit")
