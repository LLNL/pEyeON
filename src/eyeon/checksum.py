import eyeon.observe as O


def Checksum(file:str, hash:str, expected_checksum:str):
    #Get the md5 hash of the file
    fileHash= O.Observe.create_hash(file, hash)
    print(f"hash: {fileHash}")
    print(f"expected hash: {expected_checksum}")

    #compare it to the expected checksum, returns true if match
    if fileHash == expected_checksum:
        print("Checksum verification pass")
    else:
        print("Checksum verification fail, double check the expected md5 checksum provided. Otherwise file may have been modified")

