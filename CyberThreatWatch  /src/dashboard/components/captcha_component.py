import streamlit as st
import requests
import time

def st_hcaptcha(site_key: str, secret_key: str, key="captcha") -> bool:
    """
    Streamlit hCaptcha component — fully automatic version.
    Shows hCaptcha widget, captures token via JS, and verifies it silently.
    Returns True if verification passes, False otherwise.
    """

    # Initialize session state
    if key not in st.session_state:
        st.session_state[key] = {"token": None, "verified": False}

    # Inject hCaptcha widget + JS listener
    st.markdown(
        f"""
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        <div class="h-captcha" data-sitekey="{site_key}" data-callback="onHCaptchaSuccess"></div>
        <script>
        function onHCaptchaSuccess(token) {{
            const streamlitInput = window.parent.document.querySelector('textarea[data-testid="stTextAreaInput"]');
            if (streamlitInput) {{
                streamlitInput.value = token;
                streamlitInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
            }}
        }}
        </script>
        """,
        unsafe_allow_html=True
    )

    # Hidden input field to receive token from JS
    token = st.text_area("", key=f"{key}_token_input", label_visibility="collapsed", height=1)

    # Automatically verify when token is received
    if token and not st.session_state[key]["verified"]:
        verify_url = "https://hcaptcha.com/siteverify"
        data = {"secret": secret_key, "response": token}
        try:
            response = requests.post(verify_url, data=data, timeout=5)
            result = response.json()
            if result.get("success"):
                st.session_state[key]["verified"] = True
                st.session_state[key]["token"] = token
                st.success("✅ hCaptcha verification passed!")
                time.sleep(1)
                st.experimental_rerun()
            else:
                st.error("❌ hCaptcha verification failed.")
                st.session_state[key]["token"] = None
        except Exception as e:
            st.error(f"⚠️ Verification error: {e}")

    return st.session_state[key]["verified"]