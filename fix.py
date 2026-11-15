# fix.py

with open("main.py", "r", encoding="utf-8") as f:
    content = f.read()

new_key = "ee74ef32e8917b66c192796dc8f364cfab609248f1ad067a0816837a911650fc"
content = content.replace("YOUR_VIRUSTOTAL_API_KEY_HERE", new_key)

with open("main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Done! Key updated successfully!")