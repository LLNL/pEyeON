from eyeon.file import File as hasher


def Checksum(file: str, algorithm: str, expected_checksum: str):
    # Get the md5 hash of the file
    fileHash = hasher.create_hash(file, algorithm)
    print(f"{algorithm} hash: {fileHash}")
    print(f"expected hash: {expected_checksum}")

    # compare it to the expected checksum, returns true if match
    if fileHash == expected_checksum:
        print("Checksum verification pass")
    else:
        print(
            "Checksum verification fail, double check the expected checksum provided. ",
            "Otherwise file may have been modified",
        )

    return fileHash
