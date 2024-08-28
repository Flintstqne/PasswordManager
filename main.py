import sys
import logging
import sqlite3
from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QLabel, QMessageBox, QInputDialog, QTextEdit, QFormLayout, QDialog, QComboBox
import os
import random

# Dictionary for uppercase characters
uppercase_dict = {chr(i): i for i in range(65, 91)}

# Dictionary for lowercase characters
lowercase_dict = {chr(i): i for i in range(97, 123)}

# Dictionary for symbols
symbols_dict = {chr(i): i for i in range(33, 48)}
symbols_dict.update({chr(i): i for i in range(58, 65)})
symbols_dict.update({chr(i): i for i in range(91, 97)})
symbols_dict.update({chr(i): i for i in range(123, 127)})

# Dictionary for numbers
numbers_dict = {chr(i): i for i in range(48, 58)}

# Initialize database
conn = sqlite3.connect('passwords.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
            (service TEXT, username TEXT, password TEXT)''')
conn.commit()

def open_database():
    global conn, c
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

# Set up basic logging configuration
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def load_key():
    return open("secret.key", "rb").read()

def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Encryption/Decryption
#key = Fernet.generate_key()
#save_key(key)

key = load_key()
cipher_suite = Fernet(key)



def encrypt_password(password):
    logging.debug(f"Encrypting password: {password}")
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    logging.debug(f"Encrypted password: {encrypted_password}")
    return encrypted_password

def decrypt_password(encrypted_password):
    logging.debug(f"Decrypting password: {encrypted_password}")
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        logging.debug(f"Decrypted password: {decrypted_password}")
        return decrypted_password
    except InvalidToken:
        logging.error("Invalid token: The data could not be decrypted.")
        raise ValueError("Invalid token: The data could not be decrypted.")

# Main Application Functions with Error Handling
def add_password(service, username, password):
    encrypted_password = encrypt_password(password)
    c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
            (service, username, encrypted_password))
    conn.commit()

def get_password(service, username):
    c.execute("SELECT password FROM passwords WHERE service = ? AND username = ?", (service, username))
    result = c.fetchone()
    if result:
        return decrypt_password(result[0])
    else:
        return None

def list_passwords():
    try:
        c.execute("SELECT service, username, password FROM passwords")
        results = c.fetchall()
        if results:
            formatted_passwords = ""
            service_dict = {}
            for service, username, encrypted_password in results:
                decrypted_password = decrypt_password(encrypted_password)
                if service not in service_dict:
                    service_dict[service] = []
                service_dict[service].append(f"{username}: {decrypted_password}")

            for service, user_pass_list in service_dict.items():
                formatted_passwords += f"{service.upper()}\n-----------------\n"
                formatted_passwords += "\n".join(user_pass_list) + "\n\n"

            return formatted_passwords
        else:
            return "No passwords found."
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")
    except InvalidToken as e:
        logging.error(f"Invalid token: {e}")
        raise ValueError("Invalid token: could not be decrypted.")

def update_password(service, username, new_password):
    try:
        encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()
        c.execute("UPDATE passwords SET password = ? WHERE service = ? AND username = ?", (encrypted_password, service, username))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")
    except ValueError as e:
        logging.error(f"Value error: {e}")
        QMessageBox.critical(None, 'Error', str(e))

def delete_password(service):
    try:
        logging.info(f"Attempting to delete password for service: {service}")
        c.execute("SELECT username FROM passwords WHERE service = ?", (service,))
        users = c.fetchall()
        if not users:
            raise ValueError(f"No users found for the specified service: {service}")

        if len(users) > 1:
            # Prompt the user to select the username
            usernames = [user[0] for user in users]
            username, ok = QInputDialog.getItem(None, "Select User", "Select the user to delete:", usernames, 0, False)
            if not ok:
                logging.info("User canceled the delete operation.")
                return
        else:
            username = users[0][0]

        c.execute("DELETE FROM passwords WHERE service = ? AND username = ?", (service, username))
        conn.commit()
        QMessageBox.information(None, 'Success', f'Password for {username} at {service} deleted successfully!')
        logging.info(f"Password for {username} at {service} deleted successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")
    except ValueError as e:
        logging.error(f"Value error: {e}")
        QMessageBox.critical(None, 'Error', str(e))

def purge_database():
    try:
        c.execute("DELETE FROM passwords")
        conn.commit()
        logging.info("Database purged successfully.")
        # Shut down the application
        sys.exit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")

def delete_password(service):
    try:
        logging.info(f"Attempting to delete password for service: {service}")
        c.execute("SELECT username FROM passwords WHERE service = ?", (service,))
        users = c.fetchall()
        if not users:
            raise ValueError(f"No users found for the specified service: {service}")

        if len(users) > 1:
            # Prompt the user to select the username
            usernames = [user[0] for user in users]
            username, ok = QInputDialog.getItem(None, "Select User", "Select the user to delete:", usernames, 0, False)
            if not ok:
                logging.info("User canceled the delete operation.")
                return
        else:
            username = users[0][0]

        c.execute("DELETE FROM passwords WHERE service = ? AND username = ?", (service, username))
        conn.commit()
        QMessageBox.information(None, 'Success', f'Password for {username} at {service} deleted successfully!')
        logging.info(f"Password for {username} at {service} deleted successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")
    except ValueError as e:
        logging.error(f"Value error: {e}")
        QMessageBox.critical(None, 'Error', str(e))

def generate_random_password(length=None):
    # If length is not provided, choose a random length between 10 and 16
    if length is None:
        length = random.randint(10, 16)
    elif length < 8 or length > 16:
        raise ValueError("Password length must be between 10 and 16 characters.")
    print(length)

    # Define the character pools
    uppercase_chars = list(uppercase_dict.keys())
    lowercase_chars = list(lowercase_dict.keys())
    number_chars = list(numbers_dict.keys())
    symbol_chars = list(symbols_dict.keys())

    # Adjust the weights for character selection
    char_pool = (
        uppercase_chars * 3 +  # More common
        lowercase_chars * 3 +  # More common
        number_chars * 2 +     # Less common
        symbol_chars           # Least common
    )

    # Generate the password
    random_password = ''.join(random.choice(char_pool) for _ in range(length))
    return random_password

def get_services():
    try:
        c.execute("SELECT DISTINCT service FROM passwords")
        services = c.fetchall()
        return [service[0] for service in services]
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")

def get_users_for_service(service):
    try:
        c.execute("SELECT username FROM passwords WHERE service=?", (service,))
        users = c.fetchall()
        return [user[0] for user in users]
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")

def save_database():
    try:
        if conn is None:
            raise RuntimeError("Database error: Cannot operate on a closed database.")
        conn.commit()
        #QMessageBox.information(None, 'Success', 'Database saved successfully!')
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise RuntimeError(f"Database error: {e}")
# PyQt5 GUI
class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Manager')
        self.setGeometry(100, 100, 400, 300)

        # Set the application style
        QApplication.setStyle('Fusion')

        # Apply a stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #f56042;
                color: white;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #d14024;
            }
        """)

        layout = QVBoxLayout()

        self.add_btn = QPushButton('Add Password', self)
        self.add_btn.clicked.connect(self.add_password_dialog)
        layout.addWidget(self.add_btn)

        self.list_btn = QPushButton('List Passwords', self)
        self.list_btn.clicked.connect(self.list_passwords_dialog)
        layout.addWidget(self.list_btn)

        self.text_box = QTextEdit(self)
        self.text_box.setReadOnly(True)
        layout.addWidget(self.text_box)

        self.update_btn = QPushButton('Update Password', self)
        self.update_btn.clicked.connect(self.update_password_dialog)
        layout.addWidget(self.update_btn)

        self.delete_btn = QPushButton('Delete Password', self)
        self.delete_btn.clicked.connect(self.delete_password_dialog)
        layout.addWidget(self.delete_btn)

        self.purge_btn = QPushButton('Purge All Passwords', self)
        self.purge_btn.clicked.connect(self.purge_database_dialog)
        layout.addWidget(self.purge_btn)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def save_password(self, dialog, service, username, password):
        if not service or not username or not password:
            QMessageBox.warning(self, 'Error', 'All fields are required!')
            return

        # Check for duplicate users
        c.execute("SELECT username FROM passwords WHERE service = ?", (service,))
        existing_users = c.fetchall()
        if any(user[0] == username for user in existing_users):
            QMessageBox.warning(self, 'Error', f'Username {username} already exists for service {service}.')
            return

        try:
            encrypted_password = encrypt_password(password)
            c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", (service, username, encrypted_password))
            conn.commit()
            QMessageBox.information(self, 'Success', f'Password for {username} at {service} added successfully!')
            dialog.accept()
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            QMessageBox.critical(self, 'Error', f'Database error: {e}')
        except ValueError as e:
            logging.error(f"Value error: {e}")
            QMessageBox.critical(self, 'Error', f'Value error: {e}')

    def closeEvent(self, event):
        save_database()
        event.accept()

    def add_password_dialog(self):
        # Fetch existing services from the database
        c.execute("SELECT DISTINCT service FROM passwords")
        services = [row[0] for row in c.fetchall()]

        dialog = QDialog(self)
        dialog.setWindowTitle('Add Password')
        layout = QFormLayout(dialog)

        service_input = QComboBox(dialog)
        service_input.setEditable(True)
        service_input.addItems(services)

        username_input = QLineEdit(dialog)
        password_input = QLineEdit(dialog)

        generate_btn = QPushButton('Generate Password', dialog)
        generate_btn.clicked.connect(lambda: password_input.setText(generate_random_password()))

        save_btn = QPushButton('Save', dialog)
        save_btn.clicked.connect(lambda: self.save_password(dialog, service_input.currentText(), username_input.text(), password_input.text()))

        layout.addRow('Service:', service_input)
        layout.addRow('Username:', username_input)
        layout.addRow('Password:', password_input)
        layout.addRow(generate_btn, save_btn)

        dialog.setLayout(layout)
        dialog.exec_()

    def list_passwords_dialog(self):
        try:
            passwords = list_passwords()
            self.text_box.setText(passwords)
        except RuntimeError as e:
            QMessageBox.critical(self, 'Error', str(e))

    def delete_password_dialog(self):
        services = get_services()
        if services:
            service, ok = QInputDialog.getItem(self, 'Delete Password', 'Select service:', services, 0, False)
            if ok and service:
                try:
                    delete_password(service)
                except ValueError as e:
                    QMessageBox.warning(self, 'Error', str(e))
                except RuntimeError as e:
                    QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'No services found.')

    def update_password_dialog(self):
        services = get_services()
        if services:
            service, ok = QInputDialog.getItem(self, 'Update Password', 'Select service:', services, 0, False)
            if ok and service:
                users = get_users_for_service(service)
                if users:
                    if len(users) > 1:
                        username, ok = QInputDialog.getItem(self, 'Update Password', 'Select username:', users, 0, False)
                    else:
                        username = users[0]
                        ok = True
                    if ok and username:
                        new_password, ok = QInputDialog.getText(self, 'Update Password', 'Enter new password:')
                        if ok:
                            try:
                                update_password(service, username, new_password)
                                QMessageBox.information(None, 'Success', f'Password for {username} at {service} updated successfully!')
                            except ValueError as e:
                                QMessageBox.warning(self, 'Error', str(e))
                            except RuntimeError as e:
                                QMessageBox.critical(self, 'Error', str(e))
                else:
                    QMessageBox.warning(self, 'Error', 'No users found for this service.')
        else:
            QMessageBox.warning(self, 'Error', 'No services found.')

    def purge_database_dialog(self):
        reply = QMessageBox.question(self, 'Purge All Passwords',
                                    "Are you sure you want to purge all passwords and wipe the database?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                purge_database()
            except RuntimeError as e:
                QMessageBox.critical(self, 'Error', str(e))

if __name__ == '__main__':
    open_database()
    app = QApplication(sys.argv)
    ex = PasswordManager()
    app.aboutToQuit.connect(save_database)
    ex.show()
    sys.exit(app.exec_())