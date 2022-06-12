#!/usr/bin/env python3
#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Command-line interface for secret_kv package"""


import base64
from typing import Optional, Sequence, List, Union, Dict, TextIO

import os
import sys
import argparse
import argcomplete # type: ignore[import]
import json
from base64 import b64encode, b64decode
import colorama # type: ignore[import]
from colorama import Fore, Back, Style
import subprocess
from io import TextIOWrapper
from secret_kv.internal_types import JsonableTypes

from secret_kv.value import (
    validate_simple_jsonable,
    xjson_decode,
    xjson_decode_simple_jsonable,
    xjson_encode_simple_jsonable
  )

from secret_kv import (
    set_kv_store_default_passphrase,
    get_kv_store_default_passphrase,
    set_kv_store_passphrase,
    get_kv_store_passphrase
  )

def is_colorizable(stream: TextIO) -> bool:
  is_a_tty = hasattr(stream, 'isattry') and stream.isatty()
  return is_a_tty

# NOTE: this module runs with -m; do not use relative imports
from secret_kv import (
    __version__ as pkg_version,
    create_kv_store,
  )
from secret_kv import (
    KvStoreConfig,
    KvStore,
    KvValue,
    locate_kv_store_config_file,
    load_kv_store_config,
    delete_kv_store,
    Jsonable,
    JsonableDict,
    XJsonable,
    XJsonableDict
  )
from secret_kv.util import full_name_of_type, full_type

class CmdExitError(RuntimeError):
  exit_code: int

  def __init__(self, exit_code: int, msg: Optional[str]=None):
    if msg is None:
      msg = f"Command exited with return code {exit_code}"
    super(msg)
    self.exit_code = exit_code

class ArgparseExitError(CmdExitError):
  pass

class NoExitArgumentParser(argparse.ArgumentParser):
  def exit(self, status=0, message=None):
    if message:
        self._print_message(message, sys.stderr)
    raise ArgparseExitError(status, message)

class CommandHandler:
  _argv: Optional[Sequence[str]]
  _parser: argparse.ArgumentParser
  _args: argparse.Namespace
  _cwd: str
  _config_file: Optional[str] = None
  _store_config: Optional[KvStoreConfig] = None
  _store: Optional[KvStore] = None
  _scan_parent_dirs: bool = True
  _erase_db: bool = False
  _passphrase: Optional[str] = None
  _raw_stdout: TextIO = sys.stdout
  _raw_stderr: TextIO = sys.stderr
  _colorize_stdout: bool = False
  _colorize_stderr: bool = False
  _compact: bool = False
  _raw: bool = False
  _encoding: str
  _output_file: Optional[str] = None

  def __init__(self, argv: Optional[Sequence[str]]=None):
    self._argv = argv

  def ocolor(self, codes: str) -> str:
    return codes if self._colorize_stdout else ""

  def ecolor(self, codes: str) -> str:
    return codes if self._colorize_stderr else ""

  def abspath(self, path: str) -> str:
    return os.path.abspath(os.path.join(self._cwd, os.path.expanduser(path)))

  def get_config_file(self) -> str:
    if self._config_file is None:
      self._config_file = locate_kv_store_config_file(config_path=self._cwd, scan_parent_dirs=self._scan_parent_dirs)
    return self._config_file

  def get_config(self) -> KvStoreConfig:
    if self._store_config is None:
      self._store_config = load_kv_store_config(config_path=self.get_config_file())
    return self._store_config

  def get_kv_store(self) -> KvStore:
    if self._store is None:
      cfg = self.get_config()
      self._store = cfg.open_store(erase=self._erase_db, passphrase=self._passphrase)
    return self._store
    
  def pretty_print(
        self, any_value: Union[XJsonable, KvValue],
        compact: Optional[bool]=None,
        colorize: Optional[bool]=None,
        raw: Optional[bool]=None,
        simple_json: bool=False
      ):
    if isinstance(any_value, KvValue):
      kv: KvValue = any_value
    else:
      if simple_json:
        kv = KvValue(xjson_encode_simple_jsonable(validate_simple_jsonable(any_value)))
      else:
        kv = KvValue(any_value)
    value: Jsonable = kv.json_data
    xvalue: XJsonable = kv.data

    if raw is None:
      raw = self._raw
    if raw:
      if isinstance(xvalue, str):
        self._raw_stdout.write(xvalue)
        return
      elif isinstance(xvalue, (bytes, bytearray)):
        self._raw_stdout.flush()
        with os.fdopen(self._raw_stdout.fileno(), "wb", closefd=False) as bin_stdout:
          bin_stdout.write(xvalue)
          bin_stdout.flush()
        return

    if simple_json:
      value = xjson_decode_simple_jsonable(value)

    if compact is None:
      compact = self._compact
    if colorize is None:
      colorize = True

    def emit_to(f: TextIO):
      final_colorize = colorize and ((f is sys.stdout and self._colorize_stdout) or (f is sys.stderr and self._colorize_stderr))

      if not final_colorize:
        if compact:
          json.dump(value, f, separators=(',', ':'), sort_keys=True)
        else:
          json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
      else:
        jq_input = json.dumps(value, separators=(',', ':'), sort_keys=True)
        cmd = [ 'jq' ]
        if compact:
          cmd.append('-c')
        cmd.append('.')
        with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=f) as proc:
          proc.communicate(input=json.dumps(value, separators=(',', ':'), sort_keys=True).encode('utf-8'))
          exit_code = proc.returncode
        if exit_code != 0:
          raise subprocess.CalledProcessError(exit_code, cmd)

    output_file = self._output_file
    if output_file is None:
      emit_to(sys.stdout)
    else:
      with open(output_file, "w", encoding=self._encoding) as f:
        emit_to(f)


  def cmd_bare(self) -> int:
    print("A command is required", file=sys.stderr)
    return 1

  def cmd_clear_database(self) -> int:
    self._erase_db = True
    kv = self.get_kv_store()
    print(f"{kv} successfully cleared.", file=sys.stderr)
    return 0

  def cmd_delete_store(self) -> int:
    config_file = self.get_config_file()
    store_desc = delete_kv_store(config_file, scan_parent_dirs=False)
    print(f"secret-cv store with config at '{store_desc}' successfully deleted.", file=sys.stderr)
    return 0

  def cmd_test(self) -> int:
    return 0

  def cmd_create_store(self) -> int:
    args = self._args
    parent_dir = self.abspath(args.parent_dir)
    passphrase: Optional[str] = args.passphrase

    db = create_kv_store(parent_dir, passphrase=passphrase)

    print(f"Successfully created .secret-kv store under {parent_dir}", file=sys.stderr)
    return 0

  def cmd_del(self) -> int:
    args = self._args
    key: str = args.key
    store = self.get_kv_store()
    if not store.has_key(key):
      raise KeyError(f"del: key \"{key}\" does not exist")
    store.delete_value(key)
    return 0

  def cmd_get(self) -> int:
    args = self._args
    simple_json: bool = args.simple_json
    key: str = args.key
    store = self.get_kv_store()
    kv = store.get_value(key)
    if kv is None:
      raise KeyError(f"get: key \"{key}\" does not exist")
    self.pretty_print(kv, simple_json=simple_json)
    return 0

  def cmd_get_tag(self) -> int:
    args = self._args
    simple_json: bool = args.simple_json
    key: str = args.key
    tag_name: str = args.tag_name
    store = self.get_kv_store()
    kv = store.get_tag(key, tag_name)
    if kv is None:
      raise KeyError(f"get-tag: key \"{key}\", tag \"{tag_name}\" does not exist")
    self.pretty_print(kv, simple_json=simple_json)
    return 0

  def cmd_keys(self) -> int:
    store = self.get_kv_store()
    keys = list(store.keys())
    self.pretty_print(keys)
    return 0

  def _set_helper(self, cmd_name: str="set") -> KvValue:
    args = self._args
    encoding: str = args.text_encoding
    value_s: Optional[str] = args.value
    value_type_s: Optional[str] = args.value_type

    if args.vtype_json:
      if value_type_s is None:
        value_type_s = 'json'
      elif value_type_s != 'json':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and json")
    if args.vtype_int:
      if value_type_s is None:
        value_type_s = 'int'
      elif value_type_s != 'int':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and int")
    if args.vtype_float:
      if value_type_s is None:
        value_type_s = 'float'
      elif value_type_s != 'float':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and float")
    if args.vtype_bool:
      if value_type_s is None:
        value_type_s = 'bool'
      elif value_type_s != 'bool':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and bool")
    if args.vtype_xjson:
      if value_type_s is None:
        value_type_s = 'xjson'
      elif value_type_s != 'xjson':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and xjson")
    if args.vtype_binary:
      if value_type_s is None:
        value_type_s = 'binary'
      elif value_type_s != 'binary':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and binary")
    if args.vtype_base64:
      if value_type_s is None:
        value_type_s = 'base64'
      elif value_type_s != 'base64':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and base64")
    if value_type_s is None:
      value_type_s = 'str'
    use_stdin: bool = args.use_stdin
    input_file: Optional[str] = args.input_file
    if use_stdin:
      if input_file is None:
        input_file = '/dev/stdin'
      else:
        raise ValueError(f"{cmd_name}: Conflicting value input sources, --stdin and \"{input_file}\"")
    value: XJsonable
    if input_file is None:
      if value_s is None:
        raise ValueError("{cmd_name}: One of <value>, --stdin, or --input <filename> must be provided.")
      if value_type_s == 'binary':
        value = value_s.encode(encoding)
      else:
        value = value_s
    else:
      if not value_s is None:
        raise ValueError("{cmd_name}: <value> must be omitted if -i, --input, or --stdin is provided.")
      if value_type_s == 'binary':
        with open(input_file, 'rb') as bf:
          value = bf.read()
      else:
        with open(input_file, 'r', encoding=encoding) as f:
          value = f.read()

    if value_type_s == 'base64':
      try:
        value = b64decode(value, validate=True)
      except Exception as ex:
        raise ValueError(f"{cmd_name}: Invalid base-64 encoded string: {ex}") from ex
      value_type_s = 'binary'

    if value_type_s == 'int':
      try:
        value = int(value)
      except ValueError as ex:
        raise ValueError(f"{cmd_name}: Invalid integer literal") from ex
    elif value_type_s == 'float':
      try:
        value = float(value)
      except ValueError as ex:
        raise ValueError(f"{cmd_name}: Invalid float literal") from ex
    elif value_type_s == 'bool':
      assert isinstance(value, str)
      value = value.lower()
      if value in [ 'true', 't', 'yes', 'y', '1' ]:
        value = 'true'
      elif value in [ 'false', 'f', 'no', 'n', '0' ]:
        value = 'false'
      else:
        raise ValueError(f"{cmd_name}: Invalid boolean literal: '{value}'")
    elif value_type_s == 'json':
      try:
        json_data = json.loads(value)
        xjson_data = xjson_encode_simple_jsonable(json_data)
        value = xjson_decode(xjson_data)
      except json.JSONDecodeError as ex:
        raise ValueError(f"set: Invalid JSON text: {ex}") from ex
    elif value_type_s == 'xjson':
      try:
        xjson_data = json.loads(value)
        value = xjson_decode(xjson_data)
      except json.JSONDecodeError as ex:
        raise ValueError(f"set: Invalid extended JSON text: {ex}") from ex
    elif value_type_s in [ 'str', 'binary' ]:
      pass

    kv = KvValue(value)

    return kv

  def cmd_set(self) -> int:
    args = self._args
    key: str = args.key
    clear_tags: bool = args.clear_tags
    kv = self._set_helper("set")
    tags: Dict[str, KvValue] = {}
    
    store = self.get_kv_store()
    store.set_value_and_tags(key, kv, tags, clear_tags=clear_tags)

    return 0

  def cmd_set_tag(self) -> int:
    args = self._args
    key: str = args.key
    tag_name: str = args.tag_name
    kv = self._set_helper("set")
    
    store = self.get_kv_store()
    store.set_tag(key, tag_name, kv)

    return 0

  def cmd_set_default_passphrase(self) -> int:
    args = self._args
    passphrase: Optional[str] = args.new_passphrase
    if passphrase is None:
      passphrase = self._passphrase
    if passphrase is None:
      try:
        config_file = self.get_config_file()
        passphrase = get_kv_store_passphrase(config_file)
      except Exception:
        pass
    if passphrase is None:
      raise RuntimeError("A passphrase must be supplied as an arg (or with -p or --passphrase); e.g., 'secret-kv set-default-passphrase <my-passphrase>'")
    set_kv_store_default_passphrase(passphrase)
    return 0

  def cmd_get_default_passphrase(self) -> int:
    passphrase = get_kv_store_default_passphrase()
    self.pretty_print(passphrase)
    return 0

  def cmd_reset_passphrase(self) -> int:
    args = self._args
    passphrase: Optional[str] = args.new_passphrase
    if passphrase is None:
      passphrase = self._passphrase
    if passphrase is None:
      raise RuntimeError("A passphrase must be supplied as an arg (or with -p or --passphrase); e.g., 'secret-kv reset-passphrase <my-passphrase>'")
    config_file = self.get_config_file()
    set_kv_store_passphrase(config_file, passphrase)
    return 0

  def cmd_update_passphrase(self) -> int:
    args = self._args
    new_passphrase: str = args.new_passphrase
    config_file = self.get_config_file()
    store = self.get_kv_store()
    store.update_passphrase(new_passphrase)
    # NOTE: A failure here could leave DB and keychain out of sync
    set_kv_store_passphrase(config_file, new_passphrase)
    return 0

  def cmd_get_passphrase(self) -> int:
    config_file = self.get_config_file()
    passphrase = get_kv_store_passphrase(config_file)
    self.pretty_print(passphrase)
    return 0

  def cmd_version(self) -> int:
    self.pretty_print(pkg_version)
    return 0

  def run(self) -> int:
    """Run the secret-kv command-line tool with provided arguments

    Args:
        argv (Optional[Sequence[str]], optional):
            A list of commandline arguments (NOT including the program as argv[0]!),
            or None to use sys.argv[1:]. Defaults to None.

    Returns:
        int: The exit code that would be returned if this were run as a standalone command.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Access a secret key/value database.")


    # ======================= Main command

    self._parser = parser
    parser.add_argument('--traceback', "--tb", action='store_true', default=False,
                        help='Display detailed exception information')
    parser.add_argument('-M', '--monochrome', action='store_true', default=False,
                        help='Output to stdout/stderr in monochrome. Default is to colorize if stream is a compatible terminal')
    parser.add_argument('-c', '--compact', action='store_true', default=False,
                        help='Compact instead of pretty-printed output')
    parser.add_argument('-r', '--raw', action='store_true', default=False,
                        help='''Output raw strings and binary content directly, not json-encoded.
                                Values embedded in structured results are not affected.''')
    parser.add_argument('-o', '--output', dest="output_file", default=None,
                        help='Write output value to the specified file instead of stdout')
    parser.add_argument('--text-encoding', default='utf-8',
                        help='The encoding used for text. Default  is utf-8')
    parser.add_argument('-C', '--cwd', default='.',
                        help="Change the effective directory used to search for configuration")
    parser.add_argument('--config',
                        help="Specify the location of the config file")
    parser.add_argument('-p', '--passphrase', default=None,
                        help='''The passphrase to be used for accessing the store. By default, the
                                passphrase saved in the keyring will be used, or the global
                                default secret-kv passphrase (in the keyring) will be used for new stores''')
    parser.set_defaults(func=self.cmd_bare)

    subparsers = parser.add_subparsers(
                        title='Commands',
                        description='Valid commands',
                        help='Additional help available with "<command-name> -h"')

                
    # ======================= keys

    parser_version = subparsers.add_parser('version', 
                            description='''Display version information. JSON-quoted string. If a raw string is desired, user -r.''')
    parser_version.set_defaults(func=self.cmd_version)

    # ======================= test

    parser_test = subparsers.add_parser('test', description="Run a simple test. For debugging only.  Will be removed.")
    parser_test.set_defaults(func=self.cmd_test)

    # ======================= create-store

    parser_create = subparsers.add_parser('create-store', description="Create a new secret key-value store")
    parser_create.add_argument('parent_dir',
                        help='The parent directory under which a ".secret-kv" subdirectory will be created')
    parser_create.set_defaults(func=self.cmd_create_store)

    # ======================= delete-store

    parser_delete_store = subparsers.add_parser('delete-store', description="Deletes the secret-kv store, including database, config, and .secret-kv directory")
    parser_delete_store.set_defaults(func=self.cmd_delete_store)

    # ======================= clear-database

    parser_clear_database = subparsers.add_parser('clear-database', description="Erases all content in the database without deleting it")
    parser_clear_database.set_defaults(func=self.cmd_clear_database)

    # ======================= set

    def add_set_arguments(parser_set: argparse.ArgumentParser):
      parser_set.add_argument('-t', '--type', dest='value_type', default=None, choices= [ 'str', 'int', 'float', 'bool', 'json', 'base64', 'binary' 'xjson'],
                          help='''Specify how the provided input for the value is interpreted. Default is "str". "base64"
                                  will decode a base64 string into a binary value. "xjson" will accept JSON with special
                                  interpretation of "@xjson-type" properties''')
      parser_set.add_argument('-x', '--xjson', dest="vtype_xjson", action='store_true', default=False,
                          help='short for --type=xjson')
      parser_set.add_argument('--json', dest="vtype_json", action='store_true', default=False,
                          help='short for --type=json')
      parser_set.add_argument('--int', dest="vtype_int", action='store_true', default=False,
                          help='short for --type=int')
      parser_set.add_argument('--float', dest="vtype_float", action='store_true', default=False,
                          help='short for --type=float')
      parser_set.add_argument('--bool', dest="vtype_bool", action='store_true', default=False,
                          help='short for --type=bool')
      parser_set.add_argument('--binary', dest="vtype_binary", action='store_true', default=False,
                          help='short for --type=binary')
      parser_set.add_argument('--base64', dest="vtype_base64", action='store_true', default=False,
                          help='short for --type=base64')
      parser_set.add_argument('--stdin', dest="use_stdin", action='store_true', default=False,
                          help='Read the value from stdin instead of the commandline')
      parser_set.add_argument('-i', '--input', dest="input_file", default=None,
                          help='Read the value from the specified file instead of the commandline')

    parser_set = subparsers.add_parser('set', description="Set the value associated with a key")
    parser_set.add_argument('key',
                        help='The key name for which a value is being set')
    parser_set.add_argument('value', nargs='?', default=None,
                        help='The value to assign to the key. By default, interpreted as a string value. See options for interpretaton.')
    add_set_arguments(parser_set)
    parser_set.add_argument('--clear-tags', action='store_true', default=False,
                        help='Clear all previously existing tags for the key')
    parser_set.set_defaults(func=self.cmd_set)

    # ======================= set-tag

    parser_set_tag = subparsers.add_parser('set-tag', description="Set the value associated with a named tag on a particular key")
    parser_set_tag.add_argument('key',
                        help='The key name for which a tag value is being set')
    parser_set_tag.add_argument('tag_name',
                        help='The tag name for which a tag value is being set')
    parser_set_tag.add_argument('value', nargs='?', default=None,
                        help='The value to assign to the tag. By default, interpreted as a string value. See options for interpretaton.')
    add_set_arguments(parser_set_tag)
    parser_set_tag.set_defaults(func=self.cmd_set_tag)

    # ======================= get

    parser_get = subparsers.add_parser('get', description="Get the value associated with a key")
    parser_get.add_argument('key',
                        help='The key name for which the value is being fetched')
    parser_get.add_argument('-j', '--simple-json', action='store_true', default=False,
                        help='''Outputs the value as simple JSON with no special escaping of "@xjson_type" properties.
                                Will fail with error if the value is not simple JSON.''')
    parser_get.add_argument('--with-tags', action='store_true', default=False,
                        help='Outputs a JSON dict with a "value" property and a "tags" property. overrides --raw')
    parser_get.set_defaults(func=self.cmd_get)

    # ======================= get_tag

    parser_get_tag = subparsers.add_parser('get-tag', description="Get the value associated with a named tag on a particular key")
    parser_get_tag.add_argument('key',
                        help='The key name for which a tag value is being fetched')
    parser_get_tag.add_argument('tag_name',
                        help='The tag name for which a tag value is being fetched')
    parser_get_tag.add_argument('-j', '--simple-json', action='store_true', default=False,
                        help='''Outputs the tag value as simple JSON with no special escaping of "@xjson_type" properties.
                                Will fail with error if the value is not simple JSON.''')
    parser_get_tag.set_defaults(func=self.cmd_get_tag)

    # ======================= del

    parser_del = subparsers.add_parser('del', description="Delete the value and all tags associated with a key")
    parser_del.add_argument('key',
                        help='The key name for which the value and tags should be deleted')
    parser_del.set_defaults(func=self.cmd_del)

    # ======================= keys

    parser_keys = subparsers.add_parser('keys', description="Get a list of the keys in the store")
    parser_keys.set_defaults(func=self.cmd_keys)

    # ======================= set-default-passphrase

    parser_set_default_passphrase = subparsers.add_parser('set-default-passphrase',
                        description='''Set the default passphrase for newly created stores.''')
    parser_set_default_passphrase.add_argument('new_passphrase', nargs='?', default=None,
                        help='''The new store passphrase to be saved in the keychain. If
                                not provided, the passphrase provided with -p, or the
                                passphrase associated with the current store will be used.''')
    parser_set_default_passphrase.set_defaults(func=self.cmd_set_default_passphrase)

    # ======================= get-default-passphrase

    parser_get_default_passphrase = subparsers.add_parser('get-default-passphrase',
                        description='''Get the default passphrase for newly created stores.
                                       In JSON quoted string format by default; use -r for raw string.''')
    parser_get_default_passphrase.set_defaults(func=self.cmd_get_default_passphrase)

    # ======================= reset-passphrase

    parser_reset_passphrase = subparsers.add_parser('reset-passphrase',
                        description='''Hard reset the passphrase saved in keyring for the store.
                                       Does *not* update the actual passphrase with which the store is encrypted.
                                       The new passphrase can be provided with -p or as a positional argument.
                                       This command is useful when the keyring entry is lost and must be reset.''')
    parser_reset_passphrase.add_argument('new_passphrase', nargs='?', default=None,
                        help='The new store passphrase to be saved in the keychain.')
    parser_reset_passphrase.set_defaults(func=self.cmd_reset_passphrase)

    # ======================= update-passphrase

    parser_update_passphrase = subparsers.add_parser('update-passphrase',
                        description='''Re-encrypt the store with a new passphrase, and update the passphrase saved in keyring.
                                       Requires the previous passphrase to be saved in keyring or provided with -p.
                                       This update is not transactional, and a failure during update may leave the database
                                       and keyring in inconsistent states.''')
    parser_update_passphrase.add_argument('new_passphrase',
                        help='The new passphrase for the store.')
    parser_update_passphrase.set_defaults(func=self.cmd_update_passphrase)

    # ======================= get-passphrase

    parser_get_passphrase = subparsers.add_parser('get-passphrase',
                        description='''Get the passphrase used to access the store, as saved in keyring.
                                       In JSON quoted string format by default; use -r for raw string.''')
    parser_get_passphrase.set_defaults(func=self.cmd_get_passphrase)

    # =========================================================

    argcomplete.autocomplete(parser)
    try:
      args = parser.parse_args(self._argv)
    except ArgparseExitError as ex:
      return ex.exit_code
    traceback: bool = args.traceback
    try:
      self._args = args
      self._raw_stdout = sys.stdout
      self._raw_stderr = sys.stderr
      self._raw = args.raw
      self._compact = args.compact
      self._output_file = args.output_file
      self._encoding = args.text_encoding
      monochrome: bool = args.monochrome
      if not monochrome:
        self._colorize_stdout = is_colorizable(sys.stdout)
        self._colorize_stderr = is_colorizable(sys.stderr)
        if self._colorize_stdout or self._colorize_stderr:
          colorama.init(wrap=False)
          if self._colorize_stdout:
            sys.stdout = colorama.AnsiToWin32(sys.stdout)
          if self._colorize_stderr:
            sys.stderr = colorama.AnsiToWin32(sys.stderr)

        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
          self._colorize_stdout = True
        if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
          self._colorize_stderr = True
      self._cwd = os.path.abspath(os.path.expanduser(args.cwd))
      self._passphrase = args.passphrase
      config_file: Optional[str] = args.config
      if not config_file is None:
        self._config_file = self.abspath(config_file)
      rc = args.func()
    except Exception as ex:
      if isinstance(ex, CmdExitError):
        rc = ex.exit_code
      else:
        rc = 1
      if rc != 0:
        if traceback:
          raise

        print(f"{self.ecolor(Fore.RED)}secret-kv: error: {ex}{self.ecolor(Style.RESET_ALL)}", file=sys.stderr)
    return rc

def run(argv: Optional[Sequence[str]]=None) -> int:
  try:
    rc = CommandHandler(argv).run()
  except CmdExitError as ex:
    rc = ex.exit_code
  return rc

# allow running with "python3 -m", or as a standalone script
if __name__ == "__main__":
  sys.exit(run())
