import tarfile
import os.path
import argparse
import pyAesCrypt


class Backup:

    def __init__(self, source_path, output_filename, output_path, verbose, password, encypt, decrypt):
        self.source_path = source_path
        self.output_filename = output_filename
        self.output_path = output_path
        self.output_filename_crypt = f'{output_filename}.aes'
        self.verbose = verbose
        self.encrypt = encypt
        self.decrypt = decrypt
        self.password = password

    def logging(self, msg):
        if self.verbose:
            print(f'{msg}')

    def make_tarfile(self):
        """function that make a new tar file"""
        try:
            os.chdir(self.output_path)

            with tarfile.open(self.output_filename, 'w:gz') as tar:
                tar.add(self.source_path, arcname=os.path.basename(self.source_path))
            self.logging(f'[+] Successfully make compressed tar file at {self.output_path}')

            if self.encrypt:
                self.encrpyt_backup()

        except Exception as e:
            self.logging(f'[!] {e}')

    def encrpyt_backup(self):
        pyAesCrypt.encryptFile(infile='test.tar.gz', outfile=self.output_filename_crypt, passw=self.password)
        os.remove(self.output_filename)
        self.logging('[+] Backup encrypted')

    def decrypt_backup(self):
        pyAesCrypt.decryptFile(infile=self.source_path, outfile=self.output_path, passw=self.password)
        self.logging('[+] Successfully decrypted Backup')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='backuppy', description='Create and or upload compressed tar file to your google drive')

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
    parser.add_argument('-e', '--encrypt', default=True, required=False, action=argparse.BooleanOptionalAction,
                        help='Encrypt Backup'),
    parser.add_argument('-d', '--decrypt', default=True, required=False, action=argparse.BooleanOptionalAction,
                        help='Decrypt Backup'),

    args = parser.parse_args()

    obj = Backup(source_path=args.src_path, output_filename=args.out_file, output_path=args.out_path, verbose=args.verbose, password=args.passwd, encypt=args.encrypt, decrypt=args.decrypt)
    Backup.make_tarfile(obj)
