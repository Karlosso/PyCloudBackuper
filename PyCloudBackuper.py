import tarfile
import os.path
import argparse
import pyAesCrypt


class CreateBackups:

    def __init__(self, src_path, out_file, out_path, verbose, password, encypt):
        self.src_path = src_path
        self.out_file = out_file
        self.out_path = out_path
        self.verbose = verbose
        self.out_file_crypt = f'{out_file}.aes'
        self.encrypt = encypt
        self.password = password

    def __logging(self, msg):
        if self.verbose:
            print(f'{msg}')

    def make_tarfile(self):
        """function that make a new tar file"""

        try:
            os.chdir(self.out_path)

            with tarfile.open(self.out_file, 'w:gz') as tar:
                tar.add(self.src_path, arcname=os.path.basename(self.src_path))
            self.__logging(f'[+] Successfully make compressed tar file at {self.out_path}')

            if self.encrypt:
                self.__encrpyt_backup()

        except Exception as e:
            self.__logging(f'[!] {e}')

    def __encrpyt_backup(self):
        """function that encrypt the backup"""

        pyAesCrypt.encryptFile(infile='test.tar.gz', outfile=self.out_file_crypt, passw=self.password)
        os.remove(self.out_file)
        self.__logging('[+] Backup encrypted')


class DecryptBackups:

    def __init__(self, src_path, out_path, passwd, verbose):
        self.src_path = src_path
        self.out_path = out_path
        self.passwd = passwd
        self.verbose = verbose

    def __logging(self, msg):
        if self.verbose:
            print(f'{msg}')

    def decrypt_backup(self):
        """function that decrypt backup"""

        try:
            pyAesCrypt.decryptFile(infile=self.src_path, outfile=self.out_path, passw=self.passwd)
            self.__logging('[+] Successfully decrypted Backup')
        except Exception as e:
            self.__logging(f'[!] {e}')


if __name__ == '__main__':

    # Parser Config
    parser = argparse.ArgumentParser(prog='backuppy',
                                     description='Create and or upload compressed tar file to your google drive')

    # Paser Arguments
    parser.add_argument('-c', '--create', default=False, required=False, action=argparse.BooleanOptionalAction,
                        help='Create Backup'),
    parser.add_argument('-d', '--decrypt', default=False, required=False, action=argparse.BooleanOptionalAction,
                        help='Decrypt Backup'),
    parser.add_argument('-e', '--encrypt', default=True, required=False, action=argparse.BooleanOptionalAction,
                        help='Encrypt Backup'),
    parser.add_argument('-s', '--src_path', type=str, nargs='?',
                        help='Source path of your file or folder')
    parser.add_argument('-o', '--out_path', required=False, type=str, nargs='?',
                        default='./output', help='Output path for the compressed tar file')
    parser.add_argument('-f', '--out_file', type=str, nargs='?',
                        help='Output filename for your compressed tar file')
    parser.add_argument('-v', '--verbose', default=False, required=False, action=argparse.BooleanOptionalAction,
                        help='Run in verbose mode'),
    parser.add_argument('-p', '--passwd', required=False, type=str, nargs='?',
                        help='Password used to encrypt Backup'),

    args = parser.parse_args()


    if (args.create is True) and (args.decrypt is False):
        obj = CreateBackups(
            src_path=args.src_path,
            out_file=args.out_file,
            out_path=args.out_path,
            verbose=args.verbose,
            password=args.passwd,
            encypt=args.encrypt,
        )

        CreateBackups.make_tarfile(obj)

    elif (args.decrypt is True) and (args.create is False):
        obj = DecryptBackups(
            src_path=args.src_path,
            out_path=args.out_path,
            passwd=args.passwd,
            verbose=args.verbose,
        )

        DecryptBackups.decrypt_backup(obj)

    else:
        print('[!] Create backup and decrypt at the same moment is not possible')
        exit()
