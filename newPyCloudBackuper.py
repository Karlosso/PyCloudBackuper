import tarfile
import os.path
import argparse
import pyAesCrypt
from getpass import getpass
from pyicloud import PyiCloudService


class CreateBackup:
    """Class to create new Backup"""

    def __init__(self, source:str, destination:str, verbose:bool=True, encrypt:bool=True):
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


class CloudOperations:
    """Class for Cloud Operations"""

    def __int__(self):
        self.api = ""
        self.__connect_to_icloud()

    def __connect_to_icloud(self):
        """Function to connect to icloud"""

        password = getpass('Cloud Password: ')
        self.api = PyiCloudService(apple_id='mail@schulte-manuel.de', password=password)

    def list_drive(self):
        self.api.drive.dir()


new_object = CreateBackup(
    source='/Users/manuelschulte/test/folder_to_backup',
    destination='/Users/manuelschulte/test/',
)

new_object.create()
