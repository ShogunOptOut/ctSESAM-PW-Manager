from hashlib import pbkdf2_hmac

lower_case_letters = list("abcdefghijklmnopqrstuvwxyz")             # die "Buchstabensuppe"
upper_case_letters = list("ABCDEFGHJKLMNOPQRSTUVWXYZ")              # in der Liste der zu benutzenden Buchstaben lassen wir das große "I" und "O" weg (Verwechslungsgefahr mit "l" oder "0")
numbers = list("0123456789")                                        
special_characters = list("#!§$%&/()=-_+*<>;:.")                        # wie kriege ich """ integriert???? (!!!!!!!!!!)

password_characters = lower_case_letters + upper_case_letters + numbers + special_characters # Liste der verfügbaren Zeichen wird erstellt

# das "salt" ist quasi der "SEED". Also auf welcher "Buchstaben-Basis" der Hash erzeugt wird /
# ( !!! Muss natürlich wie das MP und die Domain zeichengleich sein, wenn man auch gleiche Ergebnisse haben möchte)
salt = "pepper"

def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder = "big")
    password = ""
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password


master_password = input("Masterpasswort: ")
domain = input("Domain: ")                                          # darauf achten, ob man "https//www." o.ä. mitnimmt oder weglässt
hash_string = domain + master_password
hashed_bytes = pbkdf2_hmac("sha512", hash_string.encode("utf-8"), salt.encode("utf-8"), 4096)
print("Passwort: " + convert_bytes_to_password(hashed_bytes, 10))

