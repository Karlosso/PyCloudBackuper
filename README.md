# PyCloudBackuper

## What is PyCloudBackuper?
PyCloudBackuper create encrypt compressed tar files and upload it to Apple iCloud Drive. It can be used for automatic cron backups.

## How to install?
First clone Repository

```console
git clone https://github.com/Karlosso/PyCloudBackuper.git
```
Change directory

```console
cd PyCloudBackuper
```

Then install all requirements

```console
pip install -r requirements.txt
```

Launch the Python program help list

```console
python PyCloudBackuper.py --help
```

## Example

To upload a compressed and encrypted backup to your Apple iCloud Drive, you can do the following:


First create a new secure system keyring for your Apple id

```console
python PyCloudBackuper.py --add-apple-keyring test@apple.id
```

After submitting the previous command you will be asked to enter your apple id password and 2fa authentication code.
Important! Your credentials will only be stored locally in the system keyring.

Next, a new backup can be created using the following commandlet. Other arguments can be found in the help list.

```console
python PyCloudBackuper.py --compress --encrypt --upload --input "/Backup/folder_to_Backup" --output /Backup/ --apple-id "test@apple.id"
```

To delete your Apple id from system keyring use the following command

```console
python PyCloudBackuper.py --delete-apple-keyring test@apple.id
```

To delete your Backup password from system keyring use the following command

```console
python PyCloudBackuper.py --delete-backup-keyring
```

## Errors

in the current pyicloud python libary (https://github.com/picklepete/pyicloud), which is mandatory for PyCloudBackuper, 
the following error may occur: "KeyError: "clientid".
To solve this bug manually from the libary you can follow this issue post: https://github.com/picklepete/pyicloud/issues/384
