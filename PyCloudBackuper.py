import datetime
import tarfile
import os.path
import sys
import click
import argparse
import time
import pyAesCrypt
from datetime import datetime
from getpass import getpass
from pyicloud import PyiCloudService
from pyicloud import utils as PyiCloudUtils
import keyring
import keyring.util.platform_ as keyring_platform


class SystemBackupKeyring:
    """Class for system Backup keyrings"""

    def __init__(self):
        self.namespace = "PyCloudBackuper"
        self.username = "BackupKey"

        keyring_platform.config_root()
        # /home/username/.config/python_keyring  # Might be different for you

        keyring.get_keyring()

    def create_backup_keyring(self) -> None:
        """Create new Backup system keyring"""

        keyring.set_password(
            service_name=self.namespace,
            username=self.username,
            password=getpass(log(level="INTERACTION", message="Enter Backup Password: ", return_str=True))
        )

        log(
            level="INFO",
            message="System backup key ring successfully created",
            values={"Namespace": self.namespace, "Entry": self.username}
        )

    def delete_backup_keyring(self) -> None:
        """Delete Backup system keyring"""

        keyring.delete_password(service_name=self.namespace, username=self.username)
        log(
            level="INFO",
            message="System backup key ring successfully deleted",
            values={"Namespace": self.namespace, "Entry": self.username}
        )

    def get_backup_keyring(self) -> str:
        """Get Backup system keyring"""

        # If None create new Keyring
        if keyring.get_credential(service_name=self.namespace, username=self.username) is None:
            self.create_backup_keyring()

        passwd = keyring.get_password(service_name=self.namespace, username=self.username)
        return str(passwd)  # Return Backup password


class CreateBackup(SystemBackupKeyring):
    """Class to create new Backup"""

    def __init__(self, source: str, destination: str, verbose: bool = True, encrypt: bool = True):
        super().__init__()
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

        log("INFO", message="New compressed tar file created", values={"New File": f"{self.filename}.tar.gz"})

    def __encrypt_backup(self):
        """Function to encrypt backup"""

        pyAesCrypt.encryptFile(
            infile=f'{self.filename}.tar.gz',
            outfile=f'{self.filename}.backup',
            passw=self.get_backup_keyring()
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


class DecryptBackup(SystemBackupKeyring):
    """Class to encrypt backup"""

    def __init__(self, source: str, destination: str, verbose: bool = True):
        super().__init__()
        self.source = source,
        self.destination = destination,
        self.verbose = verbose,

        # Path and File
        self.filepath = os.path.split(source)[0]
        self.filename = os.path.split(source)[1]

    def __decrypt_tar_file(self):
        """Function to decrypt tar file"""

        with tarfile.open(f'{self.filename}.tar.gz') as tar:
            tar.extractall()

        log(level="INFO", message="Local Backup successfully unpacked")

        os.remove(f'{self.filename}.tar.gz')

    def __decrypt_backup(self):
        """Function to decrypt backup"""

        pyAesCrypt.decryptFile(
            infile=self.filename,
            outfile=f'{self.filename}.tar.gz',
            passw=self.get_backup_keyring()
        )

        log(level="INFO", message="Local Backup successfully decrypted")

    def decrypt(self):
        try:
            os.chdir(self.filepath)
            self.__decrypt_backup()
            self.__decrypt_tar_file()

        except Exception as error:
            log(level="ERROR", message=str(error))
            exit()


class ICloudOperations:
    """Class for ICloud Operations"""

    def __init__(self, apple_id: str):
        self.api = None
        self.apple_id = apple_id

        self.check_apple_keyring()
        self.authenticate_to_icloud()
        self.__check_backup_folder()

    @staticmethod
    def create_keyring(username):
        """Function to create a secure iCloud system keyring"""

        password = getpass(prompt=log(level="INTERACTION", message="Enter Apple Account Password: ", return_str=True))
        PyiCloudUtils.store_password_in_keyring(username, password=password)  # create new keyring
        log(level="INFO", message="Apple Credentials saved in System Keyring", values={"Apple ID": username})

    @staticmethod
    def delete_keyring(username):
        """Function to delete a secure iCloud system keyring"""

        PyiCloudUtils.delete_password_in_keyring(username)  # delete keyring
        log(level="INFO", message="Apple Credentials deleted from system keyring", values={"Apple ID": username})

    def check_apple_keyring(self):
        """Function that checks if a keyring exists for the given user"""

        if not PyiCloudUtils.password_exists_in_keyring(username=self.apple_id):
            self.create_keyring(username=self.apple_id)

    def authenticate_to_icloud(self):
        """Function to connect to iCloud"""

        self.api = PyiCloudService(apple_id=self.apple_id, cookie_directory=False)

        # 2fa authentication
        if self.api.requires_2fa:
            code = input(log(level="INTERACTION", message="Two-Factor-Authentication code: ", return_str=True))
            result = self.api.validate_2fa_code(code)
            log(level="INFO", message=f"Two-Factor-Authentication code validation result", values={"Result": result})

            if not result:
                log(level="ERROR", message="Failed to verify Two-Factor-Authentication code")
                sys.exit(1)

            if not self.api.is_trusted_session:
                log(level="INFO", message="Session is not trusted. Requesting trust...")
                result = self.api.trust_session()
                log(level="INFO", message="Session trust result", values={"Result": result})

                if not result:
                    log(level="ERROR", message="Failed to request trust. You will likely be prompted for the code "
                                               "again in the coming weeks")
        elif self.api.requires_2sa:

            log(level="INFO", message="Two-step authentication required. Your trusted devices are:")

            devices = self.api.trusted_devices
            for i, device in enumerate(devices):
                print(
                    "  %s: %s" % (i, device.get('deviceName',
                                                "SMS to %s" % device.get('phoneNumber')))
                )

            device = click.prompt('Which device would you like to use?', default=0)
            device = devices[device]
            if not self.api.send_verification_code(device):
                log(level="ERROR", message="Failed to send verification code")
                sys.exit(1)

            code = click.prompt('Please enter validation code')
            if not self.api.validate_verification_code(device, code):
                log(level="ERROR", message="Failed to verify verification code")
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
        upload_filename = f"{cur_date}_{filename}"

        os.chdir(path)
        os.rename(src=filename, dst=upload_filename)

        with open(upload_filename, "rb") as stream:
            self.api.drive["Backup"]["PyCloudBackups"].upload(stream)
            time.sleep(5)  # Wait 5 seconds before renaming files

        log(level="INFO", message="Backup uploaded successfully", values={"Upload File": upload_filename})

        os.remove(upload_filename)  # Remove Backup File from local System
        log(level="INFO", message="Local Backup deleted successfully", values={"Local Backup": upload_filename})

    def delete_oldest_backup_file(self, max_backup_files: int = 2):
        """delete oldest backup file"""

        files = self.api.drive["Backup"]["PyCloudBackups"].dir()
        new_list = []

        for file in files:
            stream = self.api.drive["Backup"]["PyCloudBackups"][f"{file}"]
            new_dict = {"filename": stream.name, "date_modified": stream.date_modified}

            new_list.append(new_dict)

        sorted_list_of_backups = sorted(new_list, key=lambda d: d['date_modified'], reverse=True)

        list_counter = 0
        while_counter = len(sorted_list_of_backups)

        while max_backup_files < while_counter:
            list_counter = list_counter - 1  # get list entry
            file = sorted_list_of_backups[list_counter]
            self.api.drive["Backup"]["PyCloudBackups"][f"{file['filename']}"].delete()  # delete old backup files
            while_counter = while_counter - 1

            log(level="INFO", message="Backup file deleted", values={"Backup file": file["filename"]})


def log(level: str = "INFO", message: str = None, values=None, return_str: bool = False):
    current_date = datetime.now()
    values_list = ""

    if values is not None:
        values_list = f" - Values : {values}"

    if return_str is True:
        return f"{current_date} - [{level}] {message}{values_list}"
    else:
        if args.verbose:
            sys.stdout.write(f"{current_date} - [{level}] {message}{values_list}\n")

        if level == "ERROR":
            exit()


def init_parser():
    """init argument parser"""

    # Parser Config
    parser = argparse.ArgumentParser(prog='PyCloudBackuper',
                                     description='Compress decrypt and upload compressed encrypted tar file to your '
                                                 'apple icloud')

    # Parser
    parser.add_argument("-c", "--compress", required=False, action=argparse.BooleanOptionalAction,
                        help="Create Tar Backup"),

    parser.add_argument('-e', '--encrypt', required=False, action=argparse.BooleanOptionalAction,
                        help='Encrypt Backup'),
    parser.add_argument('-d', '--decrypt', required=False, action=argparse.BooleanOptionalAction,
                        help='Decrypt Backup'),

    parser.add_argument('-i', '--input', required=False, type=str, help='Source path of your file or folder')
    parser.add_argument('-o', '--output', required=False, type=str, help='Output path for the compressed tar file')

    parser.add_argument('-u', '--upload', required=False, type=bool, action=argparse.BooleanOptionalAction,
                        help='Upload compressed tar file to Apple iCloud')
    parser.add_argument('--max-backups', required=False, type=int, default=2,
                        help='Maximum number of iCloud backups that are stored')

    parser.add_argument('-v', '--verbose', default=True, required=False, action=argparse.BooleanOptionalAction,
                        help='Run in verbose mode'),

    parser.add_argument('--add-backup-keyring', required=False, type=bool, action=argparse.BooleanOptionalAction,
                        help='Add your Backup credentials to secure System keyring')
    parser.add_argument('--delete-backup-keyring', required=False, type=bool, action=argparse.BooleanOptionalAction,
                        help='Delete your Backup credentials from secure System keyring')

    parser.add_argument('-a', '--apple-id', required=False, type=str)
    parser.add_argument('--add-apple-keyring', required=False, type=str, help='Add your Apple '
                                                                              'credentials to secure System keyring')
    parser.add_argument('--delete-apple-keyring', required=False, type=str, help='Delete your Apple '
                                                                                 'credentials from secure System '
                                                                                 'keyring')

    return parser.parse_args()


def check_bad_args(args):
    """check bad combinations of arguments"""

    if (args.add_apple_keyring is not None or args.delete_apple_keyring is not None) and \
            (args.compress or args.decrypt or args.encrypt):
        log(level="ERROR", message="When argument --add-apple-keyring or --delete-apple-keyring set no other "
                                   "operations are permitted")

    elif (args.add_apple_keyring is True) and (args.delete_apple_keyring is True):
        log(level="ERROR", message="Argument --add-apple-keyring and --delete-apple-keyring can"
                                   " not run at both")

    elif (args.add_backup_keyring is not None or args.delete_backup_keyring is not None) and \
            (args.compress or args.decrypt or args.encrypt):
        log(level="ERROR", message="When argument --add-backup-keyring or --delete-backup-keyring set no other "
                                   "operations are permitted")

    elif (args.add_backup_keyring is True) and (args.delete_backup_keyring is True):
        log(level="ERROR", message="Argument --add-backup-keyring and --delete-backup-keyring can"
                                   " not run at both")

    elif args.compress and args.decrypt:
        log(level="ERROR", message="Can not compress and decrypt at the same time")

    elif args.encrypt and args.decrypt:
        log(level="ERROR", message="Can not encrypt and decrypt at the same time")

    elif (args.compress or args.encrypt or args.decrypt) and \
            (args.input is None and args.output is None):
        log(level="ERROR", message="Argument --input and --output is required")

    elif args.decrypt and args.apple_id:
        log(level="ERROR", message="Decryption do not need an apple id",
            values={"Decypt": args.decrypt, "Apple ID": args.apple_id})

    elif (args.apple_id is None) and args.upload:
        log(level="ERROR", message="You need an apple id to upload files")


if __name__ == "__main__":

    try:

        args = init_parser()
        check_bad_args(args=args)

        backup_keyring = SystemBackupKeyring()  # Init system keyring

        if args.add_apple_keyring:
            ICloudOperations.create_keyring(username=args.add_apple_keyring)
        elif args.delete_apple_keyring:
            ICloudOperations.delete_keyring(username=args.delete_apple_keyring)
        elif args.add_backup_keyring:
            backup_keyring.create_backup_keyring()
        elif args.delete_backup_keyring:
            backup_keyring.delete_backup_keyring()

        if args.compress:
            obj = CreateBackup(
                source=args.input,
                destination=args.output,
                verbose=args.verbose,
                encrypt=args.encrypt,
            )

            obj.create()

            if args.upload:
                obj = ICloudOperations(
                    apple_id=args.apple_id
                )

                obj.upload_new_backup(source=f"{args.input}.backup")

                time.sleep(5)  # Wait 5 seconds before uploading files
                obj.delete_oldest_backup_file(max_backup_files=args.max_backups)

        if args.decrypt:
            obj = DecryptBackup(
                source=args.input,
                destination=args.output,
                verbose=args.verbose,
            )

            obj.decrypt()

    except Exception as error:
        log(level="ERROR", message=str(error))
