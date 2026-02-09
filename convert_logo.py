import base64

def get_base64_logo(path):
    try:
        with open(path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode()
    except Exception as e:
        print(f"Error loading logo: {e}")
        return None

logo_path = r"c:\Users\coron\Downloads\SUBES\buholzl.jpg"
b64_logo = get_base64_logo(logo_path)

if b64_logo:
    with open("logo_b64.txt", "w") as f:
        f.write(b64_logo)
