from ANGELITA_128 import ANGELITA_128

try:
    A128 = ANGELITA_128()
    A128.setKeyH("9EED2CCA88AE43C061529DE479923836") #Enter key from encryption here

    print("Decrypting file(s)...")
    A128.decrypt("n1.jpg.ANGELITA128", "cbc")
    A128.decrypt("t1.txt.ANGELITA128", "ecb")
    print("Decryption complete.")

except Exception as e:
    print(e)