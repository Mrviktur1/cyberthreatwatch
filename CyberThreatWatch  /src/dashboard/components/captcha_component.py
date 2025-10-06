import streamlit as st
import streamlit.components.v1 as components

def st_hcaptcha(site_key: str, key="hcaptcha"):
    """
    Embed an hCaptcha widget and return the verification token once completed.
    Works in Streamlit Cloud or GitHub deployments.
    """
    captcha_html = f"""
    <div id="hcaptcha-container">
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        <div class="h-captcha" data-sitekey="{site_key}" data-callback="onVerify"></div>
        <script>
        function onVerify(token) {{
            window.parent.postMessage({{isStreamlitMessage: true, type: "setComponentValue", value: token}}, "*");
        }}
        </script>
    </div>
    """
    token = components.html(captcha_html, height=140, key=key)
    return tokenat": 4,
 "nbformat_minor": 5
}
