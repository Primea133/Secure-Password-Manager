import sqlite3
import os
import crypto_mech
import re
import stat
from log_mech import log_event
from getpass import getpass

def is_safe_path(base_path, path, follow_symlinks=True):
    # Symbolic links into absolute paths
    if follow_symlinks:
        base_path = os.path.realpath(base_path)
        path = os.path.realpath(path)
    else:
        base_path = os.path.abspath(base_path)
        path = os.path.abspath(path)
    
    return os.path.commonprefix([base_path, path]) == base_path

def get_database_path():
    # Get the LOCALAPPDATA path
    appdata_path = os.getenv("LOCALAPPDATA")
    if not appdata_path:
        raise EnvironmentError("Could not find LOCALAPPDATA environment variable")
    
    # The directory path for the password manager
    secure_folder = os.path.join(appdata_path, "MyPasswordManager")

    # Test path security
    if not is_safe_path(appdata_path, secure_folder):
        raise EnvironmentError("Potentially unsafe path detected.")

    # If directory does not exist
    if not os.path.exists(secure_folder):
        # Create directory
        os.makedirs(secure_folder, exist_ok=True)

        # Read, write and execute permissions only for owner (file creator)
        os.chmod(secure_folder, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return os.path.join(secure_folder, "password_manager.db")

def create_table():
    db_path = get_database_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS data (
                        id INTEGER PRIMARY KEY, 
                        service TEXT NOT NULL,
                        username TEXT NOT NULL, 
                        password TEXT NOT NULL
                      )''')
    conn.commit()
    conn.close()
    log_event(f"Database created at: {db_path}")
    #print(f"db_stuff, line 26")

def add_credential(service, username, encrypted_password):
    db_path = get_database_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO data (service, username, password) VALUES (?, ?, ?)",
                   (service, username, encrypted_password))
    conn.commit()
    conn.close()
    log_event("Added credentials at: " + db_path)
    #print(f"db_stuff, line 37")

def read_db_contents():
    db_path = get_database_path()
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fetch all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        if not tables:
            print("No tables found in the database.")
            return

        print(f"Tables in database '{db_path}':")
        for table in tables:
            # print(f"- {table[0]}")
            print("- " + table[0])

        # Loop through each table and display its contents
        for table in tables:
            #print(f"\nContents of table '{table[0]}':")
            print("\nContents of table '" + table[0] + "':")
            #cursor.execute(f"SELECT * FROM {table[0]}")
            cursor.execute("SELECT * FROM " + table[0])
            rows = cursor.fetchall()

            # Fetch column names
            #cursor.execute(f"PRAGMA table_info({table[0]})")
            cursor.execute("PRAGMA table_info(" + table[0] + ")")
            columns = [col[1] for col in cursor.fetchall()]

            print(" | ".join(columns))
            print("-" * 40)
            for row in rows:
                print(" | ".join(map(str, row)))

        conn.close()
    except sqlite3.Error as e:
        #print(f"Error reading database: {e}")
        print("Error reading database: " + e)

def initialize():
    print("----- My Password Manager -----")
    print("---- Initializing DataBase ----")
    try:
        create_table()
    except Exception as e:
        print("Could not create table in the initialization phase: ", e)
        return
    #in_m = input("Insert Master Password for the DB: ")
    #m_hashed_decoded = hash_master_password(input("Insert Master Password for the DB: ")).decode()
    #print("Decoded Hashed Masterpass: " + m_hashed_decoded)
    while True:
        input_1 = getpass("Insert Master Password for the DB: ")
        input_2 = getpass("Confirm Master Password for the DB: ")
        if input_1 == input_2:
            #print(f"input_1: {input_1} | input_2: {input_2}")
            store_master_password(input_1)
            input_1 == None
            input_2 == None
            break

### Boolean check for Master password (and data entries)
# Return 0: No master password, no data entires
# Return 1: Master password and data entries exist
# Return 2: No master password, but data entries exist
def b_m_set() -> int:
    try:
        db_path = get_database_path()
    except Exception as e:
        print("Could not connect to DB: ", e)
        return 99

    # Determine if to return 0/1/2
    b_master_password: bool= False
    b_data_entries: bool = False

    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if a master password already exists
        cursor.execute('''
            SELECT COUNT(*) 
            FROM sqlite_master 
            WHERE type='table' AND name='master_password';
        ''')

        if cursor.fetchone()[0] == 0:
            log_event("A master password entry does not exist.")
            b_master_password = False

        cursor.execute("SELECT COUNT(*) FROM master_password")
        if cursor.fetchone()[0] > 0:
            #log_event("A master password exists in the DB")
            b_master_password = True

        # Check if data already exists
        cursor.execute('''
            SELECT COUNT(*) 
            FROM sqlite_master 
            WHERE type='table' AND name='data';
        ''')

        if cursor.fetchone()[0] == 0:
            log_event("Credentials data does not exist.")
            b_data_entries = False

        cursor.execute("SELECT COUNT(*) FROM data")
        if cursor.fetchone()[0] > 0:
            log_event("Data in the DB exists")
            b_data_entries = True
        
        conn.close()
        #print(f"b_master_password: {b_master_password} | b_data_entries: {b_data_entries}")

        # If no db entries exist at all (Creating/initializing)
        #print("1")
        if b_master_password == False and b_data_entries == False:
            #print("1")
            #conn.close()
            return 0
        
        # If data exist for both tables
        #print("2")
        if b_master_password == True and b_data_entries == True:
            #print("2")
            #conn.close()
            return 1

        # If master password does not exist, but 'data' does (likely result of a bad actor)
        #print("3")
        if b_master_password == False and b_data_entries == True:
            #print("3")
            #conn.close()
            return 2
        
        # If after Initializing there have been no entries of 'data'/credentials added
        #print("4")
        if b_master_password == True and b_data_entries == False:
            #print("4")
            #conn.close()
            return 1

    except sqlite3.Error as e:
        log_event(f"Database error: {e}")#log_event("Database error: " + e)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def store_master_password(m_password: str):
    try:
        # Hash the master password
        hashed_password = crypto_mech.hash_master_password(m_password)

        # Connect to the database
        conn = sqlite3.connect(get_database_path())
        cursor = conn.cursor()

        # Create the table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL
            );
        ''')

        # Check if a master password already exists
        cursor.execute("SELECT COUNT(*) FROM master_password")
        if cursor.fetchone()[0] > 0:
            print("A master password already exists. How did you get here?")
            return

        # Insert the hashed password
        cursor.execute("INSERT INTO master_password (password_hash) VALUES (?)", (hashed_password,))
        conn.commit()
        print("Master password has been set successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

# Returns 0 on invalid match
# Returns 1 on valid match 
# Returns 2 on no master password hash stored in db
def verify_master_password_from_db(input_password: str) -> int:
    try:
        # Connect to the database
        conn = sqlite3.connect(get_database_path())
        cursor = conn.cursor()

        # Retrieve the hashed password
        cursor.execute("SELECT password_hash FROM master_password")
        result = cursor.fetchone()

        # Check for master password and save result
        boolean_master_password: bool = False
        if not result:
            print("No master password found. How did you get here?")
            boolean_master_password = False
        else:
            boolean_master_password = True

        stored_m_hash = result[0]
        # Verify the input password
        if boolean_master_password == True:
            #print("DEBUGGING 1111")
            if crypto_mech.verify_master_password(input_password, stored_m_hash):
                print("Master password verified.")
                return 1
            else:
                print("INVALID MASTER PASSWORD!")
                return 0
        elif boolean_master_password == True:
            return 2
    except sqlite3.Error as e:
        log_event("Database error: " + e)
    except Exception as e:
        log_event("Error: " + e)
    finally:
        conn.close()

def clear_database():
    db_path = get_database_path()
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Query all table names from sqlite_master
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        # Drop each table
        for table in tables:
            table_name = table[0]
            if table_name == "sqlite_sequence":
                print(f"Skipping '{table_name}' (system table).")
                continue

            cursor.execute(f"DROP TABLE IF EXISTS {table[0]};")
            print(f"Table '{table[0]}' dropped.")

        conn.commit()
        print("Database cleared successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def add_to_db(service: str, user_name: str, input_password: str, m: str) -> bool:
    #in_p = input("Insert password: ")
    try:
        # Remove whitespace(s)
        service = service.strip()
        user_name = user_name.strip()
        input_password = input_password.strip()

        # Checking if inputs are empty
        if not service.strip() or not user_name.strip() or not input_password.strip():
            raise ValueError("Service, username, or password is empty!")
        
        # Allowing only alphabetic characters and '.' '-' symbols
        if not re.match(r'^[\w\s.-]+$', service):
            raise ValueError("Service name contains invalid characters.")
        if not re.match(r'^[\w.-]+$', user_name):
            raise ValueError("Username contains invalid characters.")
        
        # Encrypt the password
        encrypted_password = crypto_mech.encrypt_password(input_password, m)
        #print("Encrypted pass: " + encrypted_password)

        # Add the credentials to the db
        add_credential(service, user_name, encrypted_password)

        return True
    except Exception as e:
        print(f"Error: {e}")

def retrieve_from_db_decrypted(m: str):
    db_path = get_database_path()
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Query all from data
        cursor.execute("SELECT id, service, username, password FROM data")
        rows = cursor.fetchall()

        if rows:
            print("Decrypted contents of 'data': ")
            for id, service, username, encrypted_password in rows:
                try:
                    decrypted_password = crypto_mech.decrypt_password(encrypted_password, m)
                    print(f"ID: {id} | Service: {service}, Username: {username}, Password: {decrypted_password}")
                except Exception as e:
                    print(f"Decryption failed")
        else:
            print("The 'data' table is empty.")
        
        conn.close()
    except sqlite3.Error as e:
        print(f"DB Error: {e}")

def retrieve_from_db_encrypted():
    db_path = get_database_path()
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Query all from data
        cursor.execute("SELECT id, service, username, password FROM data")
        rows = cursor.fetchall()

        if rows:
            print("Encrypted contents of 'data': ")
            for id, service, username, encrypted_password in rows:
                try:
                    print(f"{id} | Service: {service}, Username: {username}, Password: {encrypted_password}")
                except Exception as e:
                    print(f"Query failed")
        else:
            print("The 'data' table is empty.")
        
        conn.close()
    except sqlite3.Error as e:
        print(f"DB Error: {e}")

def delete_from_db(row: int) -> bool:
    try:
        db_path = get_database_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM data")
        row_count = cursor.fetchone()[0]
        if not row <= row_count and row > 0:
            return False
            #raise ValueError("Not a valid row")

        cursor.execute("DELETE FROM data WHERE id = ?", (row,))
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"DB Error: {e}")

def reset_ids():
    try:
        db_path = get_database_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Begin a transaction to do lots of operations as a single operation
        cursor.execute("BEGIN TRANSACTION;")

        # Recreate the original table properties and variables to 'temp_data'
        cursor.execute("""
            CREATE TABLE temp_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        """)

        # Copy original 'data' to the 'temp_data'
        cursor.execute("""
            INSERT INTO temp_data (service, username, password)
            SELECT service, username, password FROM data;
        """)

        # Delete the original 'data'
        cursor.execute("DROP TABLE data")

        # Rename the 'temp data' to 'data' now that the original has been deleted
        cursor.execute("ALTER TABLE temp_data RENAME TO data;")

        conn.commit()
        print("IDs have been reset successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

def check_service_input(service: str) -> bool:
    # Remove whitespace(s)
    service = service.strip()
    # Checking if inputs are empty
    if not service.strip():
        return False
        #raise ValueError("Service is empty!")
    # Allowing only alphabetic characters and '.' '-' symbols
    if not re.match(r'^[\w\s.-]+$', service):
        return False
        #raise ValueError("Service name contains invalid characters.")
    return True

def check_username_input(username: str) -> bool:
    # Remove whitespace(s)
    username = username.strip()
    # Checking if inputs are empty
    if not username.strip():
        return False
        #raise ValueError("Service is empty!")
    # Allowing only alphabetic characters and '.' '-' symbols
    if not re.match(r'^[\w\s.-]+$', username):
        return False
        #raise ValueError("Service name contains invalid characters.")
    return True

def check_password_input(password: str) -> bool:
    # Remove whitespace(s)
    password = password.strip()
    # Checking if inputs are empty
    if not password.strip():
        return False
        #raise ValueError("Service is empty!")
    # Allowing only alphabetic characters and '.' '-' symbols
    if not re.match(r'^[\w\s.-]+$', password):
        return False
        #raise ValueError("Service name contains invalid characters.")
    return True