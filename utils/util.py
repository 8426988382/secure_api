from cryptography.fernet import Fernet

secret_key = 'secret_1234addfdgsft859asd23k'
private_key = b'7m98ZwXmbiAHR5d683qMS0Jglf0pmbEpnZ0JIPDFsTo='
f = Fernet(private_key)
