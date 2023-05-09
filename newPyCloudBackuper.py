import datetime
import tarfile
import os.path
import sys
import argparse
import pyAesCrypt
from getpass import getpass
from datetime import datetime
from pyicloud import PyiCloudService


class CreateBackup:
    """Class to create new Backup"""

    def __init__(self, source: str, destination: str, verbose: bool = True, encrypt: bool = True):
        self.source = source
        self.destination = destination
        self.verbose = verbose
        self.encrypt = encrypt

        # Path and File
        self.filepath = os.path.split(self.source)[0]
        self.filename = os.path.split(self.source)[1]

    def __create_tar_file(self):
        """Function to create new tar file"""

        with tarfile.open(f'{self.filename}.tar.gz', 'w:gz') as tar:
            tar.add(self.filename)

    def __encrypt_backup(self):
        """Function to encrypt backup"""

        password = getpass(prompt='Enter Password to Encrypt: ')

        pyAesCrypt.encryptFile(
            infile=f'{self.filename}.tar.gz',
            outfile=f'{self.filename}.backup',
            passw=password
        )

        os.remove(f'{self.filename}.tar.gz')

    def create(self):
        try:
            os.chdir(self.filepath)
            self.__create_tar_file()

            if self.encrypt:
                self.__encrypt_backup()

        except Exception as error:
            print(error)
            exit()


class DecryptBackup:
    """Class to encrypt backup"""

    def __init__(self, source, destination, verbose=True, password='password'):
        self.source = source,
        self.destination = destination,
        self.verbose = verbose,
        self.password = password,

        # Path and File
        self.filepath = os.path.split(source)[0]
        self.filename = os.path.split(source)[1]

    def __decrypt_tar_file(self):
        """Function to decrypt tar file"""

        with tarfile.open(f'{self.filename}.tar.gz') as tar:
            tar.extractall()

        os.remove(f'{self.filename}.tar.gz')

    def __decrypt_backup(self):
        """Function to decrypt backup"""

        password = getpass(prompt="Enter Password to Decrypt: ")

        pyAesCrypt.decryptFile(
            infile=self.filename,
            outfile=f'{self.filename}.tar.gz',
            passw=password
        )

    def decrypt(self):
        try:
            os.chdir(self.filepath)
            self.__decrypt_backup()
            self.__decrypt_tar_file()

        except Exception as error:
            print(error)
            exit()


class ICloudOperations:
    """Class for ICloud Operations"""

    def __init__(self, apple_id: str):
        self.api = None
        self.apple_id = apple_id

        self.authenticate_to_icloud()
        self.__check_backup_folder()

    def authenticate_to_icloud(self):
        """Function to connect to icloud"""

        self.api = PyiCloudService(apple_id=self.apple_id)

        # 2fa authentication
        if self.api.requires_2fa:
            print("Two-factor authentication required.")
            code = input("Enter the code you received of one of your approved devices: ")
            result = self.api.validate_2fa_code(code)
            print("Code validation result: %s" % result)

            if not result:
                print("Failed to verify security code")
                sys.exit(1)

            if not self.api.is_trusted_session:
                print("Session is not trusted. Requesting trust...")
                result = self.api.trust_session()
                print("Session trust result %s" % result)

                if not result:
                    print("Failed to request trust. You will likely be prompted for the code again in the coming weeks")
        elif self.api.requires_2sa:
            import click
            print("Two-step authentication required. Your trusted devices are:")

            devices = self.api.trusted_devices
            for i, device in enumerate(devices):
                print(
                    "  %s: %s" % (i, device.get('deviceName',
                                                "SMS to %s" % device.get('phoneNumber')))
                )

            device = click.prompt('Which device would you like to use?', default=0)
            device = devices[device]
            if not self.api.send_verification_code(device):
                print("Failed to send verification code")
                sys.exit(1)

            code = click.prompt('Please enter validation code')
            if not self.api.validate_verification_code(device, code):
                print("Failed to verify verification code")
                sys.exit(1)

    def __check_backup_folder(self):
        """Check iCloud folders to backup"""

        folders = self.api.drive.dir()

        if not "Backup" in folders:
            self.api.drive.mkdir("Backup")

        folders = self.api.drive["Backup"].dir()

        if not "PyCloudBackups" in folders:
            self.api.drive["Backup"].mkdir("PyCloudBackups")

    def upload_new_backup(self, source):
        """upload a new backup to icloud"""

        cur_date = datetime.now().strftime("%Y-%m-%d-%H-%M")  # get current date and time

        # split source full pathfile
        path = os.path.split(source)[0]
        filename = os.path.split(source)[1]

        os.chdir(path)

        with open(filename, "rb") as stream:
            self.api.drive["Backup"]["PyCloudBackups"].upload(stream)
            self.api.drive["Backup"]["PyCloudBackups"][f"{filename}"].rename(f"{cur_date}_{filename}")

    def delete_oldest_backup_file(self, max_backup_files: int = 2):
        """delete oldest backup file"""

        files = self.api.drive["Backup"]["PyCloudBackups"].dir()
        new_list = []

        for file in files:
            stream = self.api.drive["Backup"]["PyCloudBackups"][f"{file}"]
            new_dict = {}
            new_dict["filename"] = stream.name
            new_dict["date_modified"] = stream.date_modified

            new_list.append(new_dict)

        sorted_list_of_backups = sorted(new_list, key=lambda d: d['date_modified'])

        while_counter = 1
        list_counter = 0

        while max_backup_files >= while_counter:
            list_counter = list_counter - 1 # get list entry
            file = sorted_list_of_backups[list_counter]
            self.api.drive["Backup"]["PyCloudBackups"][f"{file['filename']}"].delete() # delete old backup files
            while_counter = while_counter + 1
