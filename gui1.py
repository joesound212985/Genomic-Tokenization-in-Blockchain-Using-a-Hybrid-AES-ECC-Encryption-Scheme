import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt
import subprocess

class EncryptionDecryptionGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Encryption and Decryption')
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # --- Encryption Section ---
        encrypt_layout = QHBoxLayout()
        encrypt_label = QLabel('Encrypt File:')
        encrypt_layout.addWidget(encrypt_label)

        self.encrypt_file_path = QLineEdit()
        encrypt_layout.addWidget(self.encrypt_file_path)

        select_file_button = QPushButton('Select File')
        select_file_button.clicked.connect(self.select_encrypt_file)
        encrypt_layout.addWidget(select_file_button)

        recipient_pubkey_label = QLabel('Recipient PubKey:')
        encrypt_layout.addWidget(recipient_pubkey_label)

        self.encrypt_recipient_pubkey = QLineEdit()
        encrypt_layout.addWidget(self.encrypt_recipient_pubkey)

        encrypt_button = QPushButton('Encrypt')
        encrypt_button.clicked.connect(self.encrypt_file)
        encrypt_layout.addWidget(encrypt_button)

        layout.addLayout(encrypt_layout)

        # --- Decryption Section ---
        decrypt_layout = QHBoxLayout()
        decrypt_label = QLabel('Decrypt File:')
        decrypt_layout.addWidget(decrypt_label)

        self.decrypt_file_index = QLineEdit()
        self.decrypt_file_index.setPlaceholderText('File Index')
        decrypt_layout.addWidget(self.decrypt_file_index)

        self.decrypt_ecc_secret_key = QLineEdit()
        self.decrypt_ecc_secret_key.setPlaceholderText('ECC Secret Key (Base64)')
        decrypt_layout.addWidget(self.decrypt_ecc_secret_key)

        self.decrypt_ecc_public_key = QLineEdit()
        self.decrypt_ecc_public_key.setPlaceholderText('ECC Public Key (Base64)')
        decrypt_layout.addWidget(self.decrypt_ecc_public_key)

        decrypt_button = QPushButton('Decrypt')
        decrypt_button.clicked.connect(self.decrypt_file)
        decrypt_layout.addWidget(decrypt_button)

        layout.addLayout(decrypt_layout)

        # --- Grant Access Section ---
        grant_access_layout = QHBoxLayout()
        grant_access_label = QLabel('Grant Access:')
        grant_access_layout.addWidget(grant_access_label)

        self.grant_access_file_index = QLineEdit()
        self.grant_access_file_index.setPlaceholderText('File Index')
        grant_access_layout.addWidget(self.grant_access_file_index)

        self.grant_access_address = QLineEdit()
        self.grant_access_address.setPlaceholderText('Ethereum Address')
        grant_access_layout.addWidget(self.grant_access_address)

        grant_access_button = QPushButton('Grant Access')
        grant_access_button.clicked.connect(self.grant_access)
        grant_access_layout.addWidget(grant_access_button)

        layout.addLayout(grant_access_layout)

        # --- Revoke Access Section ---
        revoke_access_layout = QHBoxLayout()
        revoke_access_label = QLabel('Revoke Access:')
        revoke_access_layout.addWidget(revoke_access_label)

        self.revoke_access_file_index = QLineEdit()
        self.revoke_access_file_index.setPlaceholderText('File Index')
        revoke_access_layout.addWidget(self.revoke_access_file_index)

        self.revoke_access_address = QLineEdit()
        self.revoke_access_address.setPlaceholderText('Ethereum Address')
        revoke_access_layout.addWidget(self.revoke_access_address)

        revoke_access_button = QPushButton('Revoke Access')
        revoke_access_button.clicked.connect(self.revoke_access)
        revoke_access_layout.addWidget(revoke_access_button)

        layout.addLayout(revoke_access_layout)

        # --- Access List Section ---
        access_list_layout = QHBoxLayout()
        access_list_label = QLabel('Access List:')
        access_list_layout.addWidget(access_list_label)

        self.access_list_file_index = QLineEdit()
        self.access_list_file_index.setPlaceholderText('File Index')
        access_list_layout.addWidget(self.access_list_file_index)

        access_list_button = QPushButton('Get Access List')
        access_list_button.clicked.connect(self.get_access_list)
        access_list_layout.addWidget(access_list_button)

        layout.addLayout(access_list_layout)

        # --- List File Indexes Button ---
        file_index_button = QPushButton('List File Indexes')
        file_index_button.clicked.connect(self.list_file_indexes)
        layout.addWidget(file_index_button)

        # --- Output Text Area ---
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        self.setLayout(layout)

    def select_encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Encrypt')
        if file_path:
            self.encrypt_file_path.setText(file_path)

    def encrypt_file(self):
        file_path = self.encrypt_file_path.text()
        recipient_pub_key = self.encrypt_recipient_pubkey.text()

        if file_path and recipient_pub_key:
            try:
                # Pass both the file path and the recipient public key to the Node.js script.
                command = ['node', 'auth1.js', '-e', file_path, recipient_pub_key]
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                if stderr:
                    self.output_text.setPlainText(f"Encryption failed:\n{stderr}")
                else:
                    self.output_text.setPlainText(stdout)
            except Exception as e:
                self.output_text.setPlainText(f"Encryption failed:\n{str(e)}")
        else:
            self.output_text.setPlainText("Please select a file and enter recipient's ECC public key (Base64).")

    def decrypt_file(self):
        file_index = self.decrypt_file_index.text()
        ecc_secret_key = self.decrypt_ecc_secret_key.text()
        ecc_public_key = self.decrypt_ecc_public_key.text()

        if file_index and ecc_secret_key and ecc_public_key:
            try:
                process = subprocess.Popen(
                    ['node', 'auth1.js', '-d', file_index, ecc_secret_key, ecc_public_key],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                if stderr:
                    self.output_text.setPlainText(f"Decryption failed:\n{stderr}")
                else:
                    self.output_text.setPlainText(stdout)
            except Exception as e:
                self.output_text.setPlainText(f"Decryption failed:\n{str(e)}")
        else:
            self.output_text.setPlainText("Please enter the file index, ECC secret key, and ECC public key.")

    def grant_access(self):
        file_index = self.grant_access_file_index.text()
        address = self.grant_access_address.text()
        if file_index and address:
            try:
                process = subprocess.Popen(
                    ['node', 'auth1.js', '-g', file_index, address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                if stderr:
                    self.output_text.setPlainText(f"Grant access failed:\n{stderr}")
                else:
                    self.output_text.setPlainText(stdout)
            except Exception as e:
                self.output_text.setPlainText(f"Grant access failed:\n{str(e)}")
        else:
            self.output_text.setPlainText("Please enter the file index and address.")

    def revoke_access(self):
        file_index = self.revoke_access_file_index.text()
        address = self.revoke_access_address.text()
        if file_index and address:
            try:
                process = subprocess.Popen(
                    ['node', 'auth1.js', '-r', file_index, address],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                if stderr:
                    self.output_text.setPlainText(f"Revoke access failed:\n{stderr}")
                else:
                    self.output_text.setPlainText(stdout)
            except Exception as e:
                self.output_text.setPlainText(f"Revoke access failed:\n{str(e)}")
        else:
            self.output_text.setPlainText("Please enter the file index and address.")

    def get_access_list(self):
        file_index = self.access_list_file_index.text()
        if file_index:
            try:
                process = subprocess.Popen(
                    ['node', 'auth1.js', '-l', file_index],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                stdout, stderr = process.communicate()
                if stderr:
                    self.output_text.setPlainText(f"Get access list failed:\n{stderr}")
                else:
                    self.output_text.setPlainText(stdout)
            except Exception as e:
                self.output_text.setPlainText(f"Get access list failed:\n{str(e)}")
        else:
            self.output_text.setPlainText("Please enter the file index.")

    def list_file_indexes(self):
        try:
            process = subprocess.Popen(
                ['node', 'auth1.js', '-i'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            if stderr:
                self.output_text.setPlainText(f"Failed to list file indexes:\n{stderr}")
            else:
                self.output_text.setPlainText(stdout)
        except Exception as e:
            self.output_text.setPlainText(f"Failed to list file indexes:\n{str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = EncryptionDecryptionGUI()
    gui.show()
    sys.exit(app.exec_())
