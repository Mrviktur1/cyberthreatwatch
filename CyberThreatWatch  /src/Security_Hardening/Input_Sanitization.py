from bleach import clean
def sanitize_input(text):
    return clean(text, strip=True)