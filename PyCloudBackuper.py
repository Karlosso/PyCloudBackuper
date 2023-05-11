import datetime
import tarfile
import os.path
import sys
import argparse
import time

import pyAesCrypt
from datetime import datetime
from pyicloud import PyiCloudService


class CreateBackup:
    """Class to create new Backup"""

    def __init__(self, source: str, destination: str, verbose: bool = True, encrypt: bool = True,
                 passwd: str = None):
        self.source = source
        self.destination = destination
        self.verbose = verbose
        self.encrypt = encrypt
        self.passwd = passwd

        # Path and File
        self.filepath = os.path.split(self.source)[0]
        self.filename = os.path.split(self.source)[1]

    def __create_tar_file(self):
        """Function to create new tar file"""

        with tarfile.open(f'{self.filename}.tar.gz', 'w:gz') as tar:
            tar.add(self.filename)

        log("INFO", message="New compressed tar file created", values={"New File": f"{self.filename}.tar.gz"})

    def __encrypt_backup(self):
        """Function to encrypt backup"""

        pyAesCrypt.encryptFile(
            infile=f'{self.filename}.tar.gz',
            outfile=f'{self.filename}.backup',
            passw=self.passwd
        )

        log("INFO", message="New encrypted backup file created", values={"New File": f"{self.filename}.backup"})

        os.remove(f'{self.filename}.tar.gz')

        log("INFO", message="None-encrypted tar file deleted", values={"Deleted File": f"{self.filename}.tar.gz"})

    def create(self):
        try:
            os.chdir(self.filepath)
            self.__create_tar_file()

            if self.encrypt:
                self.__encrypt_backup()

        except Exception as error:
            log(level="ERROR", message=f"{error}")


class DecryptBackup:
    """Class to encrypt backup"""

    def __init__(self, source: str, destination: str, verbose: bool = True, passwd: str = None):
        self.source = source,
        self.destination = destination,
        self.verbose = verbose,
        self.passwd = passwd,

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

        pyAesCrypt.decryptFile(
            infile=self.filename,
            outfile=f'{self.filename}.tar.gz',
            passw=self.passwd
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

        log("INFO", message="Apple iCloud authentication successful", values={"Apple ID": self.apple_id})

    def __check_backup_folder(self):
        """Check iCloud folders to backup"""

        folders = self.api.drive.dir()

        if not "Backup" in folders:
            self.api.drive.mkdir("Backup")
            log("INFO", message="New folder 'Backup' created in iCloud Drive under root")

        folders = self.api.drive["Backup"].dir()

        if not "PyCloudBackups" in folders:
            self.api.drive["Backup"].mkdir("PyCloudBackups")

            log("INFO", message="New folder 'PyCloudBackups' created in iCloud Drive under Backup")

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

        log("INFO", message="Upload backup file successful", values={"Upload File": f"{cur_date}_{filename}"})

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

        list_counter = 1
        while_counter = len(sorted_list_of_backups)

        while max_backup_files < while_counter:
            list_counter = list_counter - 1  # get list entry
            file = sorted_list_of_backups[list_counter]
            self.api.drive["Backup"]["PyCloudBackups"][f"{file['filename']}"].delete()  # delete old backup files
            while_counter = while_counter - 1

            log(level="INFO", message="Backup file deleted", values={"Backup file": file["filename"]})


def log(level: str = "INFO", message: str = None, values=None):
    current_date = datetime.now()
    values_list = ""

    if values is not None:
        values_list = f" - Values : {values}"

    print(f"{current_date} - [{level}] {message}{values_list}")

    if level == "ERROR":
        exit()


def init_parser():
    """init argument parser"""

    # Parser Config
    parser = argparse.ArgumentParser(prog='PyCloudBackuper',
                                     description='Compress decrypt and upload compressed encrypted tar file to your apple icloud')

    # Parser
    parser.add_argument("-c", "--compress", required=False, action=argparse.BooleanOptionalAction,
                        help="Create Tar Backup"),

    parser.add_argument('-e', '--encrypt', required=False, action=argparse.BooleanOptionalAction, help='Encrypt Backup'),
    parser.add_argument('-d', '--decrypt', required=False, action=argparse.BooleanOptionalAction, help='Decrypt Backup'),

    parser.add_argument('-i', '--input', required=True, type=str, help='Source path of your file or folder')
    parser.add_argument('-o', '--output', required=True, type=str, help='Output path for the compressed tar file')

    parser.add_argument('-u', '--upload', required=False, type=bool, action=argparse.BooleanOptionalAction,
                        help='Upload compressed tar file to Apple iCloud')
    #parser.add_argument('--max_backups', required=False, type=int, default=2,
     #                   help='Maximum number of iCloud backups that are stored')

    parser.add_argument('-v', '--verbose', default=False, required=False, action=argparse.BooleanOptionalAction,
                        help='Run in verbose mode'),
    parser.add_argument('-p', '--passwd', required=False, type=str, help='Password used to encrypt Backup'),

    parser.add_argument('-a', '--apple_id', required=False, type=str)

    return parser.parse_args()


def check_bad_args(args):
    """check bad combinations of arguments"""

    if args.compress and args.decrypt:
        log(level="ERROR", message="Can not compress and decrypt at the same time")

    if args.encrypt and args.decrypt:
        log(level="ERROR", message="Can not encrypt and decrypt at the same time")

    if args.encrypt and (args.passwd is None):
        log(level="ERROR", message="Can not encrpyt File if password is not set",
            values={"Encrpyt": args.encrypt, "Password": args.passwd})

    if args.decrypt and args.apple_id:
        log(level="ERROR", message="Decryption do not need an apple id",
            values={"Decypt": args.decrypt, "Apple ID": args.apple_id})

    if (args.apple_id is None) and (args.upload is True):
        log(level="ERROR", message="You need an apple id to upload files")


if __name__ == "__main__":

    args = init_parser()
    check_bad_args(args=args)

    if args.compress:
        obj = CreateBackup(
            source=args.input,
            destination=args.output,
            verbose=args.verbose,
            encrypt=args.encrypt,
            passwd=args.passwd,
        )

        obj.create()

        if args.upload:
            obj = ICloudOperations(
                apple_id=args.apple_id
            )

            obj.upload_new_backup(source=f"{args.input}.backup")

            time.sleep(5) # Wait 5 seconds after uploading files
            obj.delete_oldest_backup_file()

    if args.decrypt:
        obj = DecryptBackup(
            source=args.input,
            destination=args.output,
            verbose=args.verbose,
            passwd=args.passwd,
        )

        obj.decrypt()
