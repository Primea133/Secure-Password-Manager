import msvcrt
import db_stuff
from getpass import getpass
from log_mech import log_event
import time

FAILED_ATTEMPTS = 0
LOCKOUT_TIME = 10

def press_to_continue():
    print("Press any button to continue")
    if msvcrt.getch().decode():
        print("Continuing...")

def main_menu(sys_check):
    global FAILED_ATTEMPTS
    # Normal access mode
    if sys_check == 1:
        print("----- My Password Manager -----")
        if FAILED_ATTEMPTS >= 5:
            print(f"Failed to log-in {FAILED_ATTEMPTS} times")
            print(f"Timeout for {LOCKOUT_TIME} sec")
            time.sleep(LOCKOUT_TIME)
            FAILED_ATTEMPTS = 0
        print("L - Log In")
        print("E - Exit")
    
        while True:
            option = msvcrt.getch().decode()
            if option.lower() == "l":
                return 1

            if option.lower() == "e":
                return 0
    # Limited access mode
    elif sys_check == 2:
        print("---------- My Password Manager ----------")
        print("---------------- WARNING ----------------")
        print("- Master password not found in database -")
        print("------ Only retrieving is possible ------")

        print("L - Log In(Limited access)")
        print("E - Exit")

        while True:
            option = msvcrt.getch().decode()
            if option.lower() == "l":
                return 1

            if option.lower() == "e":
                return 0

def vault(master_password: str):
    while True:
        print("----- My Password Manager -----")
        print("----------- Actions -----------")
        print("A - Add")
        print("R - Retrieve")
        print("D - Delete")

        print("E - Exit")

        action = msvcrt.getch().decode()
        ### If action A: Add data to the db
        if action.lower() == "a":
            print("--- Adding new credentials ---")
            service = input("Service: ")
            username = input("Username: ")
            password = getpass("Password: ")
            ## Check input
            if not db_stuff.check_service_input(service):
                print("Invalid Service Input!")
                if not db_stuff.check_username_input(username):
                    print("Invalid Username Input!")
                    if not db_stuff.check_password_input(password):
                        print("Invalid Password Input!")

            db_stuff.add_to_db(service, username, password, master_password)
            service = None
            username = None
            password = None

            log_event("User added a new credentials")
            ### Continue the loop
            press_to_continue()
        ### If action R: Read data from the db
        if action.lower() == "r":
            db_stuff.retrieve_from_db_decrypted(master_password)

            log_event("User retrieved the credentials table")
            ### Continue the loop
            press_to_continue()
        if action.lower() == "d":
            db_stuff.retrieve_from_db_encrypted()
            try:
                id_input = input("Which ID to delete('C' to cancel): ")
                ## Canceling deletion
                if id_input.lower() == 'c':
                    continue
                id = int(id_input)
            except ValueError:
                print(f"'{id_input}' is not a valid number")
                continue
            try:
                ### Confirming input
                confirmation = input(f"Are you sure you want to delete id('yes' or 'y'): {id}? ")
                if confirmation.lower() == 'yes' or confirmation.lower() == 'y':
                    if db_stuff.delete_from_db(id):
                        db_stuff.reset_ids()
                        log_event("User deleted a credential entry")
                        print(f"Successfully deleted ID: {id}")
                    else:
                        print("Invalid row ID")
                else:
                    print("Canceled deleting process")
            except Exception:
                print("Confirmation denied")

            ### Continue the loop
            press_to_continue()
        ### If action E: Exit
        if action.lower() == "e":
            return 0

def limited_vault(master_password: str):
    while True:
        print("----- My Password Manager -----")
        print("------ Actions (Limited) ------")
        print("R - Retrieve")

        print("E - Exit")

        action = msvcrt.getch().decode()
        ### If action R: Read data from the db
        if action.lower() == "r":
            db_stuff.retrieve_from_db_decrypted(master_password)

            ### Continue the loop
            press_to_continue()
        ### If action E: Exit
        if action.lower() == "e":
            return 0

def log_in(sys_check):
    global FAILED_ATTEMPTS
    print("----- My Password Manager -----")
    print("--------- Logging in ----------")

    # Securely storing Master Password in memory
    #master_password = bytearray(input("Master Password: "), "utf-8")
    master_password = getpass("Master Password:")
    #print(f"db_stuff.verify_master_password_from_db(master_password)1: {db_stuff.verify_master_password_from_db(master_password)}")
    #print(f"sys_check: {sys_check}")
    if sys_check == 1:
        try:
            #print(f"db_stuff.verify_master_password_from_db(master_password)2: {db_stuff.verify_master_password_from_db(master_password)}")
            if db_stuff.verify_master_password_from_db(master_password) == 1:
                log_event("Logged in")
                FAILED_ATTEMPTS = 0
                vault(master_password)
            else:
                FAILED_ATTEMPTS += 1
                log_event("Invalid master password entered")
        finally:
            master_password = None
    elif sys_check == 2:
        try:
            log_event("Logged in, in (Limited access) mode")
            FAILED_ATTEMPTS = 0
            limited_vault(master_password)
        finally:
            master_password = None
    else:
        print("System check error")

def main():
    while True:
        sys_check = db_stuff.b_m_set()
        #print(f"sys_check: {sys_check}")
        # Log this strange event
        if sys_check == 2:
            log_event("No master password in database, but credentials data exists")
        # If database exists, then attempt to log-in
        if sys_check == 1 or sys_check == 2:
            action = main_menu(sys_check)
            if action == 0:
                log_event("User exited the program")
                return
            if action == 1:
                log_in(sys_check)
        else:
            db_stuff.initialize()

if __name__ == "__main__":
    #db_stuff.clear_database()
    #db_stuff.reset_ids()
    main()
    #db_stuff.read_db_contents()