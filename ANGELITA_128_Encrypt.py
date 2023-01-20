from ANGELITA_128 import ANGELITA_128

try:
    A128 = ANGELITA_128()

    #######################
    #### Catch Exceptions
    #######################

    #A128.encrypt("file", "ecb") #Key not set

    #A128.genKey()
    #A128.encrypt("file", "zzz") #Invalid mode

    #A128.setKeyH("AAAA") #Hex key too short
    
    #A128.setKeyH("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB") #Hex key too long

    #A128.setKeyH("AAAAAAAAAAAAAAAAAAAAAAzAAAAAAAAA") #Invalid hex digit
    
    #A128.setKeyS("aaaa") #String key too short
    
    #A128.setKeyS("aaaaaaaaaaaaaaaab") #String key too long
    
    ########################
    ########################

    A128.genKey()
    A128.showKey()

    print("Encrypting file(s)...")
    A128.encrypt("n1.jpg", "cbc")
    A128.encrypt("t1.txt", "ecb")
    print("Encryption complete.")

except Exception as e:
    print(e)