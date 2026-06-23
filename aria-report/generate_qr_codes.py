"""Generate the QR codes used in the dedication page.

Requires: pip install qrcode[pil]
Edit PORTFOLIO_URL below, then run this script from the aria-report directory.
"""
import os
import qrcode

PORTFOLIO_URL = "https://v0-portfolio-website-creation-eosin.vercel.app/"

os.makedirs("assets/qr", exist_ok=True)

qrcode.make("https://youtu.be/wGRF3GQ4Wdk").save("assets/qr/youtube.png")
qrcode.make(PORTFOLIO_URL).save("assets/qr/portfolio.png")

print("QR codes generated in assets/qr/")
print(f"  Portfolio URL: {PORTFOLIO_URL}")
print("  YouTube URL:   https://youtu.be/wGRF3GQ4Wdk")
