# main.py

from vault_manager import initialize, add_credential, get_credentials, delete_credential, check_id
from crypto_utils import derive_key
import password_utils

def main():
    print("Welcome to CLI Password Manager")
    
    # Authenticate user and get master password
    # master_password = initialize()
    
    # Derive encryption key from master password
    # key = derive_key(master_password)

    count = 0
    key = initialize(count)
    print(key)


    while True:
        print("\nChoose an option:")
        print("1. Add a new credential")
        print("2. View stored credentials")
        print("3. Delete a credential")
        print("4. Exit")

        choice = input("Enter choice (1-4): ").strip()

        if choice == "1":
            url = input("Enter site URL: ").strip()
            username = input("Enter username: ").strip()
            use_random = input("Generate random secure password? (y/n): ").strip().lower()
            
            if use_random == "y":
                raw_password = password_utils.generate_password()
                print(f"Generated password: {raw_password}")
            else:
                raw_password = input("Enter password: ").strip()

            add_credential(key, url, username, raw_password)

        elif choice == "2":
            credentials = get_credentials(key)
            for id_, url, user, pw in credentials:
                print("------------------------------------------------------------------")
                print(f"ID: {id_}")
                print(f"URL: {url}")
                print(f"Username: {user}")
                print(f"Password: {pw}")
                print("------------------------------------------------------------------")

        elif choice == "3":
            cred_id = input("Enter ID of credential to delete: ").strip()
            # && cred_id is present in db
            valid_ids = check_id(cred_id)
            if cred_id.isdigit() and cred_id in valid_ids:
                delete_credential(int(cred_id))
            else:
                print("Invalid ID or ID format.")

        elif choice == "4":
            print("Exiting. Stay safe!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
