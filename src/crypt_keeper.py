import argparse
import secrets
import toml

import os

DEFAULT_OUT_EXT="cck"
DEFAULT_KEY_EXT="kck"

HOME_DIR=os.path.expanduser("~")

CRYPT_FILE=f"{HOME_DIR}/.crypt"

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-e", "--encrypt", type=str, help="The file to encrypt, given as a local file path.")
    parser.add_argument("-d", "--decrypt", type=str, help="The file to decrypt, given as a local file path.")
    parser.add_argument("-c", "--clean-file-keys", action="store_true", help="Remove all file keys.")
    parser.add_argument("-r", "--remove-file-key", type=str, help="Remove the specified file key.")
    parser.add_argument("-l", "--list-file-keys", action="store_true", help="List all of the current file keys.")

    args = parser.parse_args()

    crypt = {}

    # Create the file if it does not exist
    if not os.path.exists(CRYPT_FILE):
        with open(CRYPT_FILE, "w") as temp_file:
            temp_file.write(toml.dumps(crypt))
    else:
        with open(CRYPT_FILE, "r") as temp_file:
            toml.loads(temp_file.read())

    if args.list_file_keys:
        if len(crypt.keys()) > 0 :
            print("Keys for:")
        for key in crypt.keys():
            print(f" -> {key}")
    elif args.clean_file_keys:
        pass
    elif args.remove_file_key is not None:
        pass
    elif args.encrypt is not None:
        pass
    elif args.decrypt is not None:
        pass
    else:
        parser.print_help()
        exit(0)

    # Save out any changes made to the crypt file
    with open(CRYPT_FILE, "w") as temp_file:
        temp_file.write(toml.dumps(crypt))

    return

if __name__ == "__main__":
    main()
