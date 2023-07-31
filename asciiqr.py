import io
import qrcode
def printqrcode(url):
    qr = qrcode.QRCode()
    qr.add_data(url)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    print(f.read())