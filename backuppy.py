import tarfile
import os.path
import argparse


class Backup:

    def __init__(self, source_path, output_filename, output_path, verbose):
        self.source_path = source_path
        self.output_filename = output_filename
        self.output_path = output_path
        self.verbose = verbose

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
        except Exception as e:
            self.logging(f'[!] {e}')



if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='backuppy', description='Create and or upload compressed tar file to your google drive')

    parser.add_argument('-s', '--src_path', type=str, nargs='?',
                        help='Source path of your file or folder')
    parser.add_argument('-o', '--out_path', required=False, type=str, nargs='?',
                        default='./output', help='Output path for the compressed tar file')
    parser.add_argument('-f', '--out_file', type=str, nargs='?',
                        help='Output filename for your compressed tar file')
    parser.add_argument('-v', '--verbose', default=False, required=False, action=argparse.BooleanOptionalAction,
                        help='Run in verbose mode')

    args = parser.parse_args()

    obj = Backup(source_path=args.src_path, output_filename=args.out_file, output_path=args.out_path, verbose=args.verbose)
    Backup.make_tarfile(obj)
