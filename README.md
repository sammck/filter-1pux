secret-kv: Project-local secret key/value storage
=================================================

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest release](https://img.shields.io/github/v/release/sammck/secret-kv.svg?style=flat-square&color=b44e88)](https://github.com/sammck/secret-kv/releases)

A tool and API for managing local secrets for a project.

Table of contents
-----------------

* [Introduction](#introduction)
* [Installation](#installation)
* [Usage](#usage)
  * [Command line](#command-line)
  * [API](api)
* [Known issues and limitations](#known-issues-and-limitations)
* [Getting help](#getting-help)
* [Contributing](#contributing)
* [License](#license)
* [Authors and history](#authors-and-history)


Introduction
------------

Python package `secret-kv` provides a command-line tool as well as a runtime API for managing and accessing a database of secret key/value
pairs that are scoped to a particular project, directory, etc. The entire database is encrypted using a single passphrase that is maintained
in a system keychain.

Some key features of secret-kv:

* Built on [sqlcipher](https://www.zetetic.net/sqlcipher/), an encrypted extension of [sqlite](https://www.sqlite.org/index.html) that
  applies 256-bit AES encryption to a single-file database, using a single passphrase.
* Uses [keyring](https://pypi.org/project/keyring/) to maintain the passphrase for a given database, and optionally to store a
  default passphrase to be used for newly create databases.
* Maintains separation of secrets and the key/value namespace between different projects,
  including passphrases stored in [keyring](https://pypi.org/project/keyring/).
* An entire project's secrets can be destroyed simply by deleting its database (and a single keyring secret)
* Allows a project to access its private secrets with minimal configuration.
* Finds a project's secret store from any subdirectory within the project.
* Supports full validated JSON values.
* Supports binary values.
* Allows metadata to be attached to key/value pairs in the form of tag-name/value pairs
* Key enumeration
* database export/import/merge (not yet implemented)
* A rich command-line tool:
  * JSON-formatted results available for all data retrieval operations
  * Optional colored output
  * bash tab-completion available
  * Optional raw (unquoted) results for string and binary data


Installation
------------

### Prerequisites

**Python**: Python 3.7+ is required. See your OS documentation for instructions.

**sqlcipher**: `secret-kv`` depends on [sqlcipher](https://www.zetetic.net/sqlcipher/), which is available in many OS distributions. On
ubuntu/debian, it can be installed with:

```bash
sudo apt-get install sqlcipher
```

### From PyPi

The current released version of `secret-kv` can be installed with 

```bash
pip3 install secret-kv
```

### From GitHub

[Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer) is required; it can be installed with:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Clone the repository and install secret-kv into a private virtualenv with:

```bash
cd <parent-folder>
git clone https://github.com/sammck/secret-kv.git
cd secret-kv
poetry install
```

You can then launch a bash shell with the virtualenv activated using:

```bash
poetry shell
```


Usage
=====

Command Line
------------

There is a single command tool `secret-kv` that is installed with the package.

### Setting a default database passphrase

The first time you use `secret-kv` (as an OS user), you may want to set a default passphrase
to be used for creation of new databases. This passphrase will be securely stored in
[keyring](https://pypi.org/project/keyring/) under service="python/secret-kv", username="default-db-passphrase":

```bash
secret-kv -p '<default-passphrase>' set-default-passphrase
```

The default passphrase is only used during creation of new databases; it has no effect on existing databases.
It is global to the user who sets it (i.e., global to the user's
[keyring](https://pypi.org/project/keyring/)). It is shared across all installations of `secret-kv` for the
user.

If a default passphrase is not set, it will be necessary to supply a passphrase each time a new database is created.

### Initializing a project's secret key/value store.

Creating and initializing a secret key/value store for a given project is simple. To create a store with the
default passphrase (see [above](#setting-a-default-passphrase)):

```bash
secret-kv create-store <project-root-dir>
```

Or, to explicitly set a passphrase for the new store:

```bash
secret-kv -p '<my-passphrase>' create-store <project-root-dir>
```

A new directory `<project-root-dir>/.secret-kv/` will be created that contains the encrypted database and configuration information. The
new store's passphrase is securely stored in the user's [keyring](https://pypi.org/project/keyring/), so generally the passphrase
will not need to be provided again for the life of the project.

> NOTE: The newly created `<project-root-dir>/.secret-kv/` directory includes an encrypted binary database file. While its
> contents are unreadable without the store's passphrase, binary files of this type are not particularly friendly to source control
> systems (e.g., Git). It is recommended for most applications that `.secret-kv/` be added to `.gitignore` to prevent
> checking the secret store into your Git repo.

> NOTE: The store's passphrase will be stored in [keyring](https://pypi.org/project/keyring/) under service="python/secret-kv",
> with the keyring username set to a hash of the store's pathname. This prevents stores created in different directories
> from colliding in their use of [keyring](https://pypi.org/project/keyring/), but it means that if you move your store
> to a different directory, or rename a parent directory of the store, then you will have to reinitialize the
> store's passphrase before the store can be used again. For this reason, and because the keyring might be erased,
> it is important to maintain a record of the passphrase if the contents of the store are irreplaceable.

### Setting a secret value

To set a simple string value:

```bash
cd <any-dir-under-project-root-dir>
secret-kv set <key> "<string-value>"
```

To set a JSON value (including bare int, float, bool, null, and quoted strings):

```bash
cd <any-dir-under-project-root-dir>
secret-kv set --json <key> '<json-text>'
secret-kv set --json <key> -i <json-filename>
<my-json-generating-cmd> | secret-kv set --json --stdin <key>
```

To set a binary value:

```bash
cd <any-dir-under-project-root-dir>
secret-kv set --binary --stdin <key> -i <my-binary-filename>
```

### Getting a secret value

To get a value as parseable JSON (including bare int, float, bool, null, quoted strings, dicts, and lists):

```bash
cd <any-dir-under-project-root-dir>
secret-kv get <key>
secret-kv get <key> | jq <jq-query-expression>
```
> NOTE: The default representation here is what `secret-kv` calls *xjson*. For simple json values, it is generally
> identical to the JSON that was originally set. This is always true as long as the original JSON did not contain
> any dicts with a property name that began with one or more '@' characters followed by "kv_type". If such a property
> did exist in the original JSOn, the property name will be prefixed with an additional '@' character in the
> default output format. This allows for disambiguation between simple JSON and richer types that can be embedded
> in the store (in particular, binary values). If it is essential that you get the same JSON out as you put in, even
> in this unusual edge case, and
> you know that the value does not include any extended types (e.g., binary values), you can provide a `--simple-json`
> option to the `get` command--in this case, you will get back exactly what you put in, but an error will be returned if any extended
> types are present in the value.

> NOTE: Values that were set with `--binary` or `--base64` options will appear as: 
> ```json
> { "@kv_type": "binary", "data": "<base64-encoded-binary-data>" }
> ```

To get a string or binary value back in its raw, unquoted, non-JSON form:

```bash
cd <any-dir-under-project-root-dir>
MY_SECRET="$(secret-kv -r get <key-for-string-secret>)"
secret-kv -r get <key-for-binary-secret> > <my-binary-file>
```

Using the `-r` option for values that are not simple strings or binary values has no effect.

### Deleting a secret value

To delete a secret value from the store:

```bash
cd <any-dir-under-project-root-dir>
secret-kv del <key>
```

### Deleting the store

To delete the entire store, the containing `.secret-kv/` directory, and the [keyring](https://pypi.org/project/keyring/) entry
for the store:

```bash
cd <any-dir-under-project-root-dir>
secret-kv delete-store
```

### Clearing the store

To remove all secrets from the store and restore it to its newly initialized state, without deleting the store
or changing the passphrase:

```bash
cd <any-dir-under-project-root-dir>
secret-kv clear-store
```

### Enumerating keys

To get a JSON list of all keys in the store:

```bash
cd <any-dir-under-project-root-dir>
secret-kv keys
```


API
---

TBD

Known issues and limitations
----------------------------

* Import/export are not yet supported.

Getting help
------------

Please report any problems/issues [here](https://github.com/sammck/secret-kv/issues).

Contributing
------------

Pull requests welcome.

License
-------

secret-kv is distributed under the terms of the [MIT License](https://opensource.org/licenses/MIT).  The license applies to this file and other files in the [GitHub repository](http://github.com/sammck/secret-kv) hosting this file.

Authors and history
---------------------------

The author of secret-kv is [Sam McKelvie](https://github.com/sammck).
