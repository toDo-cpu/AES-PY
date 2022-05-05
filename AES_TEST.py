from AES_Implementation import *

if __name__ == "__main__":

    print("[+] Entering in AES vector tests ...")
    
    print("[-] Testing key expansion for AES-128,AES-192 and AES-256")
    #testing key expansion for AES-128 AES-192 and AES-256
    aes_128_w = key_expansion(bytearray().fromhex("2b7e151628aed2a6abf7158809cf4f3c"))[0]
    aes_192_w = key_expansion(bytearray().fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"))[0]
    aes_256_w = key_expansion(bytearray().fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))[0]

    expected_w = {
        "aes_128" : state_from_bytes(bytearray().fromhex("2b7e151628aed2a6abf7158809cf4f3c")),
        "aes_192" : state_from_bytes(bytearray().fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")),
        "aes_256" : state_from_bytes(bytearray().fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    }
    
    for i in range(len(aes_128_w)):
        current_word = aes_128_w[i]
        expected_word = expected_w["aes_128"][i]
        assert(current_word == expected_word)
    
    for i in range(len(aes_192_w)):
        current_word = aes_192_w[i]
        expected_word = expected_w["aes_192"][i]
        assert(current_word == expected_word)
    for i in range(len(aes_256_w)):
        current_word = aes_256_w[i]
        expected_word = expected_w["aes_256"][i]
        assert(current_word == expected_word)

    print("[-] Key expansion tests done, everything good")

    assert(aes_encryption(bytearray().fromhex("00112233445566778899aabbccddeeff"), bytearray().fromhex("000102030405060708090a0b0c0d0e0f")) == bytearray().fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))