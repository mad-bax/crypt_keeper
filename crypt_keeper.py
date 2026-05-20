import argparse
import secrets
import toml
import tarfile

import hashlib

import os

DEFAULT_OUT_EXT=".ck"
DEFAULT_OUT_KEY=".kk"

HOME_DIR=os.path.expanduser("~")

CRYPT_DIR=f"{HOME_DIR}/.crypt"
CRYPT_FILE=f"{CRYPT_DIR}/keeper.toml"

def enc_file(path):

    file_size = os.path.getsize(path)

    secret = secrets.token_bytes(file_size)
    index = 0

    h = hashlib.sha3_256()

    out_bytes = bytearray()

    with open(path, "rb") as in_file:
        for c in in_file.read():
            b = c ^ secret[index]
            out_bytes.append(b)
            index+=1
        in_file.seek(0)
        h.update(in_file.read())

    orig_data_hash = h.hexdigest()

    with open(path+DEFAULT_OUT_EXT, "wb") as out_file:
        out_file.write(out_bytes)

    key_file = CRYPT_DIR+"/"+os.path.basename(path)+DEFAULT_OUT_KEY

    with open(key_file, "wb") as key_handler:
        key_handler.write(secret)

    with open(CRYPT_FILE, "r") as record_file:
        records = toml.loads(record_file.read())
        records[os.path.basename(path)] = {}
        records[os.path.basename(path)]["key"] = key_file
        records[os.path.basename(path)]["sha256_hash"] = orig_data_hash

    with open(CRYPT_FILE, "w") as record_file:
        record_file.write(toml.dumps(records))

    return

def dec_file(path):

    file_size = os.path.getsize(path)

    index = 0

    h = hashlib.sha3_256()

    out_bytes = bytearray()

    with open(CRYPT_FILE, "r") as record_file:
        records = toml.loads(record_file.read())

    base_name = os.path.basename(path)[:-3]

    key_file = records[base_name]["key"]

    key_size = os.path.getsize(key_file)

    if key_size != file_size :
        print("Key size does not match file size")
        exit(1)

    with open(key_file, "rb") as key_handler:
        secret = key_handler.read()

    with open(path, "rb") as enc_file:
        for d in enc_file.read():
            out_bytes.append(d ^ secret[index])
            index+=1

    h.update(out_bytes)

    d = h.hexdigest()

    if d != records[base_name]["sha256_hash"]:
        print("Hashes don't match")
        exit(1)

    with open(path[:-3], "wb") as data_out:
        data_out.write(out_bytes)

    del records[base_name]

    with open(CRYPT_FILE, "w") as records_file:
        records_file.write(toml.dumps(records))

    os.remove(path)
    os.remove(key_file)

    return

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-e", "--encrypt", type=str, help="The file to encrypt, given as a local path.")
    parser.add_argument("-d", "--decrypt", type=str, help="The file to decrypt, given as a local path.")
    parser.add_argument("-c", "--clean-file-keys", action="store_true", help="Remove all file keys.")
    parser.add_argument("-r", "--remove-file-key", type=str, help="Remove the specified file key.")
    parser.add_argument("-l", "--list-file-keys", action="store_true", help="List all of the current file keys.")

    args = parser.parse_args()

    crypt = {}

    # Create the file if it does not exist
    try:
        if not os.path.exists(CRYPT_FILE):
            os.mkdir(CRYPT_DIR)
            with open(CRYPT_FILE, "w") as temp_file:
                temp_file.write(toml.dumps(crypt))
        else:
            with open(CRYPT_FILE, "r") as temp_file:
                crypt = toml.loads(temp_file.read())
    except:
        print(f"Cannot open {CRYPT_FILE}")
        exit(1)

    if args.list_file_keys:
        if len(crypt.keys()) > 0 :
            print("Keys for:")
        for key in crypt.keys():
            print(f" -> {key}")
    elif args.clean_file_keys:
        with open(CRYPT_FILE, "w") as temp_file:
            temp_file.write(toml.dumps({}))
        for f in os.listdir(CRYPT_DIR):
            if not f.endswith("keeper.toml"):
                os.remove(CRYPT_DIR+"/"+f)
    elif args.remove_file_key is not None:
        if args.remove_file_key in crypt.keys():
            del crypt[args.remove_file_key]
            with open(CRYPT_FILE, "w") as temp_file:
                temp_file.write(toml.dumps(crypt))
            if os.path.exists(args.remove_file_key+".kk"):
                os.remove(args.remove_file_key+".kk")
    elif args.encrypt is not None:
        if os.path.isfile(args.encrypt):
            enc_file(args.encrypt)
        elif os.path.isdir(args.encrypt):
            print("You have directed to a directory, please compress the directory into a file before encrypting.")
            exit(0)
    elif args.decrypt is not None:
        dec_file(args.decrypt)
    else:
        parser.print_help()
        exit(0)

    return

if __name__ == "__main__":
    main()
