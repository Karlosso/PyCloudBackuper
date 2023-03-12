import tarfile
import os.path
import argparse
import pyAesCrypt


class CreateBackup:
    """Class to create new Backup"""

    def __init__(self, source, destination, verbose=True, encrypt=True, password='12345'):
        self.source = source
        self.destination = destination
        self.verbose = verbose
        self.encrypt = encrypt
        self.password = password

        # Path and File
        self.filepath = os.path.split(self.source)[0]
        self.filename = os.path.split(self.source)[1]

    def __create_tar_file(self):
        """Function to create new tar file"""

        os.chdir(self.filepath)

        with tarfile.open(f'{self.filename}.tar.gz', 'w:gz') as tar:
            tar.add(self.filepath, arcname=self.filename)

    def __encrypt_backup(self):
        """Function to encrypt backup"""

        pyAesCrypt.encryptFile(
            infile=f'{self.filename}.tar.gz',
            outfile=f'{self.filename}.backup',
            passw=self.password
        )

        os.remove(f'{self.filename}.tar.gz')

    def create(self):
        try:
            self.__create_tar_file()

            if self.encrypt:
                self.__encrypt_backup()

        except Exception as error:
            print(error)


class DecryptBackup:
    """Class to encrypt backup"""

    def __init__(self, source, destination, verbose=True, password='12345'):
        self.source = source,
        self.destination = destination,
        self.verbose = verbose,
        self.password = password,

        # Path and File
        self.filepath = os.path.split(source)[0]
        self.filename = os.path.split(source)[1]

    def __decrypt_backup(self):
        """Function to decrypt backup"""

        os.chdir(self.filepath)

        pyAesCrypt.decryptFile(
            infile=self.filename,
            outfile=f'{self.filename}.tar.gz',
            passw=self.password,
        )

    def decrypt(self):
        try:
            self.__decrypt_backup()

        except Exception as error:
            print(error)


new_object = CreateBackup(
    source='/Users/manuelschulte/test/testfile',
    destination='/Users/manuelschulte/',
    password='test'
)

test = DecryptBackup(
    source='/Users/manuelschulte/test/testfile.tar.gz',
    destination='/Users/manuelschulte/',
    password='test'
)

new_object.create()
test.decrypt()
