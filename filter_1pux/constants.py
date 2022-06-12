# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Constants used by secret_kv"""

SECRET_KV_DIR_NAME = ".secret-kv"
SECRET_KV_DB_FILENAME = "kv.db"
SECRET_KV_CONFIG_FILENAME = "secret-kv-config.json"
SECRET_KV_KEYRING_SERVICE = "python/secret-kv"
SECRET_KV_KEYRING_KEY_DEFAULT_PASSPHRASE = "default-db-passphrase"
SECRET_KV_KEYRING_KEY_FHASH_PASSPHRASE_PREFIX = "fhash/"
SECRET_KV_KEYRING_KEY_FHASH_PASSPHRASE_SUFFFIX = "/db-passphrase"
SECRET_KV_KEYRING_KEY_FHASH_PASSPHRASE_DYNAMIC = (
    SECRET_KV_KEYRING_KEY_FHASH_PASSPHRASE_PREFIX + 
    '${config_file_hash}' + 
    SECRET_KV_KEYRING_KEY_FHASH_PASSPHRASE_SUFFFIX
  )
