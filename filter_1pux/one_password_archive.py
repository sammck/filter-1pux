#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Class to encapsulate a 1password archive file"""

from __future__ import annotations

from typing import IO, TYPE_CHECKING, Union, Optional, List, Set, TypeVar, Iterable, Dict, Tuple

from types import TracebackType
import sys
import os
import struct
import json
import datetime
import calendar
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED, ZIP_STORED
from shutil import copyfileobj
from .internal_types import Jsonable, JsonableDict
from .exceptions import Filter1PuxError

if TYPE_CHECKING:
  from _typeshed import StrPath, Self
  from zipfile import _ZipFileMode

class OnePasswordItemData:
  _data: JsonableDict
  _document_ids: Set[str]

  def __init__(self, data: JsonableDict):
    self._data = data
    self._document_ids = set()
    self._add_all_document_ids(self._data)

  @property
  def item_uuid(self) -> str:
    return self._data['uuid']

  @property
  def document_ids(self) -> Set[str]:
    return self._document_ids

  @property
  def raw_data(self) -> JsonableDict:
    return self._data

  def _add_all_document_ids(self, subtree: JsonableDict | List[Jsonable]) -> None:
    if isinstance(subtree, list):
      for v in subtree:
        if isinstance(v, (dict, list)):
          self._add_all_document_ids(v)
    elif isinstance(subtree, dict):
      for k, v in subtree.items():
        if isinstance(v, (dict, list)):
          self._add_all_document_ids(v)
        elif k == 'documentId' and isinstance(v, str):
          self._document_ids.add(v)

class OnePasswordVaultData:
  _data: JsonableDict
  _items: List[OnePasswordItemData]
  _items_by_uuid: Dict[str, OnePasswordItemData]
  _document_ids: Set[str]

  def __init__(self, data: JsonableDict):
    self._data = data
    if not 'attrs' in data:
      raise Filter1PuxError('1Password archive vault is missing "attrs" property')
    if not isinstance(data['attrs'], dict):
      raise Filter1PuxError('1Password archive vault "attrs" property is not a dict')
    if not 'items' in data:
      raise Filter1PuxError('1Password archive vault is missing "items" property')
    if not isinstance(data['items'], list):
      raise Filter1PuxError('1Password archive vault "items" property is not a list')
    self._items = []
    self._items_by_uuid = {}
    self._document_ids = set()
    for item_raw_data in data['items']:
      item_data = OnePasswordItemData(item_raw_data)
      if item_data.item_uuid in self._items_by_uuid:
        raise Filter1PuxError(f'Multiple instances of item uuid {item_data.item_uuid} in vault "{self.vault_name}"')
      self._items.append(item_data)
      self._items_by_uuid[item_data.item_uuid] = item_data
      self._document_ids.update(item_data.document_ids)

  @property
  def raw_data(self) -> JsonableDict:
    return self._data

  @property
  def vault_attrs(self) -> JsonableDict:
    result = self._data['attrs']
    assert isinstance(result, dict)
    return result

  @property
  def vault_uuid(self) -> str:
    return self.vault_attrs['uuid']

  @property
  def vault_description(self) -> str:
    return self.vault_attrs.get('desc', '')

  @property
  def vault_avatar(self) -> str:
    return self.vault_attrs['avatar']

  @property
  def vault_name(self) -> str:
    return self.vault_attrs['name']

  @property
  def vault_type(self) -> str:
    return self.vault_attrs['type']

  @property
  def vault_item_list(self) -> List[OnePasswordItemData]:
    return self._items

  @property
  def vault_items_by_uuid(self) -> Dict[str, OnePasswordItemData]:
    return self._items_by_uuid

  @property
  def document_ids(self) -> Set[str]:
    return self._document_ids

  @property
  def num_items(self) -> int:
    return len(self.vault_item_list)

class OnePasswordAccountData:
  _unfiltered_data: JsonableDict
  _unfiltered_vaults: List[OnePasswordVaultData]
  _unfiltered_vaults_by_uuid: Dict[str, OnePasswordVaultData]
  _unfiltered_vaults_by_name: Dict[str, OnePasswordVaultData]
  _unfiltered_document_ids: Set[str]
  _filtered_data: JsonableDict
  _filtered_vaults: List[OnePasswordVaultData]
  _filtered_vaults_by_uuid: Dict[str, OnePasswordVaultData]
  _filtered_vaults_by_name: Dict[str, OnePasswordVaultData]
  _filtered_document_ids: Set[str]

  def __init__(self, data: JsonableDict, include_vault_names: Optional[Iterable[Optional[str]]] = None):
    self._unfiltered_data = data
    if not 'attrs' in data:
      raise Filter1PuxError('1Password archive account is missing "attrs" property')
    if not isinstance(data['attrs'], dict):
      raise Filter1PuxError('1Password archive account "attrs" property is not a dict')
    if not 'vaults' in data:
      raise Filter1PuxError('1Password archive account is missing "vaults" property')
    if not isinstance(data['vaults'], list):
      raise Filter1PuxError('1Password archive account "vaults" property is not a list')
    self._unfiltered_vaults = []
    self._unfiltered_vaults_by_uuid = {}
    self._unfiltered_vaults_by_name = {}
    self._unfiltered_document_ids = set()
    vault_name_set: Set[Optional[str]] = set([None]) if include_vault_names is None else set(include_vault_names)
    include_all_vaults = None in vault_name_set
    if include_all_vaults:
      self._filtered_vaults = self._unfiltered_vaults
      self._filtered_vaults_by_uuid = self._unfiltered_vaults_by_uuid
      self._filtered_vaults_by_name = self._unfiltered_vaults_by_name
      self._filtered_document_ids = self._unfiltered_document_ids
    else:
      self._filtered_vaults = []
      self._filtered_vaults_by_uuid = {}
      self._filtered_vaults_by_name = {}
      self._filtered_document_ids = set()

    for vault_raw_data in data['vaults']:
      vault = OnePasswordVaultData(vault_raw_data)
      if vault.vault_uuid in self._unfiltered_vaults_by_uuid:
        raise Filter1PuxError(f'Multiple instances of vault uuid {vault.vault_uuid} in account "{self.account_name}"')
      if vault.vault_name in self._unfiltered_vaults_by_name:
        raise Filter1PuxError(f'Multiple instances of vault name "{vault.vault_name}" in account "{self.account_name}"')
      self._unfiltered_vaults.append(vault)
      self._unfiltered_vaults_by_uuid[vault.vault_uuid] = vault
      self._unfiltered_vaults_by_name[vault.vault_name] = vault
      self._unfiltered_document_ids.update(vault.document_ids)
      if not include_all_vaults and (
            vault.vault_uuid in vault_name_set or
            vault.vault_name in vault_name_set
          ):
        self._filtered_vaults.append(vault)
        self._filtered_vaults_by_uuid[vault.vault_uuid] = vault
        self._filtered_vaults_by_name[vault.vault_name] = vault
        self._filtered_document_ids.update(vault.document_ids)
    if include_all_vaults:
      self._filtered_data = self._unfiltered_data
    else:
      self._filtered_data = dict(self._unfiltered_data)
      filtered_vaults_data: List[JsonableDict] = []
      for vault in self._filtered_vaults:
        filtered_vaults_data.append(vault.raw_data)
      self._filtered_data['vaults'] = filtered_vaults_data

  @property
  def unfiltered_raw_account_data(self) -> JsonableDict:
    return self._unfiltered_data

  @property
  def filtered_raw_account_data(self) -> JsonableDict:
    return self._filtered_data

  @property
  def account_attrs(self) -> JsonableDict:
    result = self._unfiltered_data['attrs']
    assert isinstance(result, dict)
    return result

  @property
  def account_uuid(self) -> str:
    return self.account_attrs['uuid']

  @property
  def account_name(self) -> str:
    return self.account_attrs['accountName']

  @property
  def account_domain(self) -> str:
    return self.account_attrs['domain']

  @property
  def account_email(self) -> str:
    return self.account_attrs['email']

  @property
  def account_avatar(self) -> str:
    return self.account_attrs['avatar']

  @property
  def owner_name(self) -> str:
    return self.account_attrs['name']

  @property
  def unfiltered_vault_list(self) -> List[OnePasswordVaultData]:
    return self._unfiltered_vaults

  @property
  def unfiltered_vaults_by_uuid(self) -> Dict[str, OnePasswordVaultData]:
    return self._unfiltered_vaults_by_uuid

  @property
  def unfiltered_vaults_by_name(self) -> Dict[str, OnePasswordVaultData]:
    return self._unfiltered_vaults_by_name

  @property
  def unfiltered_document_ids(self) -> Set[str]:
    return self._unfiltered_document_ids

  @property
  def filtered_vault_list(self) -> List[OnePasswordVaultData]:
    return self._filtered_vaults

  @property
  def filtered_vaults_by_uuid(self) -> Dict[str, OnePasswordVaultData]:
    return self._filtered_vaults_by_uuid

  @property
  def filtered_vaults_by_name(self) -> Dict[str, OnePasswordVaultData]:
    return self._filtered_vaults_by_name

  @property
  def filtered_document_ids(self) -> Set[str]:
    return self._filtered_document_ids

  @property
  def num_unfiltered_vaults(self) -> int:
    return len(self.unfiltered_vault_list)

  @property
  def num_filtered_vaults(self) -> int:
    return len(self.filtered_vault_list)

class OnePasswordArchive:
  BUFFER_SIZE: int = 1024 * 1024 * 2

  _zf: ZipFile
  _export_attributes: Optional[JsonableDict] = None
  _export_attributes_zipinfo: Optional[ZipInfo] = None
  _unfiltered_data: Optional[JsonableDict] = None
  _filtered_data: Optional[JsonableDict] = None
  _unfiltered_zipinfos: Optional[List[ZipInfo]] = None
  _filtered_zipinfos: Optional[List[ZipInfo]] = None
  _export_data_zipinfo: Optional[ZipInfo] = None
  _files_dir_zipinfo: Optional[ZipInfo] = None
  _file_document_ids: Optional[Set[str]] = None
  _unfiltered_accounts: List[OnePasswordAccountData]
  _unfiltered_accounts_by_uuid: Dict[str, OnePasswordAccountData]
  _unfiltered_accounts_by_name: Dict[str, OnePasswordAccountData]
  _unfiltered_document_ids: Set[str]
  _filtered_accounts: List[OnePasswordAccountData]
  _filtered_accounts_by_uuid: Dict[str, OnePasswordAccountData]
  _filtered_accounts_by_name: Dict[str, OnePasswordAccountData]
  _filtered_document_ids: Set[str]

  def __init__(
        self,
        file: StrPath | IO[bytes],
        mode: _ZipFileMode='r',
        include_vault_names: Optional[Iterable[Optional[str] | Tuple[Optional[str], Optional[str]]]] = None
      ):
    self._zf = ZipFile(file, mode=mode)
    self._zf.debug = 0
    account_vault_names: Dict[Optional[str], Set[Optional[str]]] = {}
    def add_account_vault_name(account_name: Optional[str], vault_name: Optional[str]) -> None:
      if account_name == '*':
        account_name = None
      if vault_name == '*':
        vault_name = None
      if not account_name in account_vault_names:
        account_vault_names[account_name] = set()
      account_vault_names[account_name].add(vault_name)

    if not include_vault_names is None:
      for include_vault_name in include_vault_names:
        if isinstance(include_vault_name, tuple):
          include_account_name, include_vault_name = include_vault_name
        else:
          include_account_name = None
        add_account_vault_name(include_account_name, include_vault_name)
    wild_account_vault_names = account_vault_names.get(None, None)
    include_all_accounts = include_vault_names is None or not wild_account_vault_names is None

    self._unfiltered_accounts = []
    self._unfiltered_accounts_by_uuid = {}
    self._unfiltered_accounts_by_name = {}
    self._unfiltered_document_ids = set()
    self._filtered_accounts = []
    self._filtered_accounts_by_uuid = {}
    self._filtered_accounts_by_name = {}
    self._filtered_document_ids = set()

    data = self.get_unfiltered_data()
    for account_data in data['accounts']:
      account_attrs = account_data['attrs']
      account_name = account_attrs['name']
      if account_name in self._unfiltered_accounts_by_name:
        raise Filter1PuxError(f"Multiple 1Password accounts with name '{account_name}'")
      account_uuid = account_attrs['uuid']
      if account_uuid in self._unfiltered_accounts_by_uuid:
        raise Filter1PuxError(f"Multiple 1Password accounts with UUID '{account_uuid}'")
      by_account_name_vault_names = account_vault_names.get(account_name, None)
      by_account_uuid_vault_names = account_vault_names.get(account_uuid, None)
      include_account = (
          include_all_accounts or
          not by_account_name_vault_names is None or
          not by_account_uuid_vault_names is None
        )
      vault_names: Set[Optional[str]] = set()
      if include_account:
        if include_vault_names is None:
          vault_names.add(None)
        if not wild_account_vault_names is None:
          vault_names.update(wild_account_vault_names)
        if not by_account_name_vault_names is None:
          vault_names.update(by_account_name_vault_names)
        if not by_account_uuid_vault_names is None:
          vault_names.update(by_account_uuid_vault_names)
        if (
              by_account_name_vault_names is None and
              by_account_uuid_vault_names is None and
              wild_account_vault_names is None
            ):
          vault_names.add(None)
      account = OnePasswordAccountData(account_data, include_vault_names=vault_names)
      self._unfiltered_accounts.append(account)
      self._unfiltered_accounts_by_uuid[account_uuid] = account
      self._unfiltered_accounts_by_name[account_name] = account
      self._unfiltered_document_ids.update(account.unfiltered_document_ids)
      if include_account:
        self._filtered_accounts.append(account)
        self._filtered_accounts_by_uuid[account_uuid] = account
        self._filtered_accounts_by_name[account_name] = account
        self._filtered_document_ids.update(account.filtered_document_ids)
    
    missing_file_document_ids = self._unfiltered_document_ids - self.file_document_ids
    if len(missing_file_document_ids) > 0:
      print(f"WARNING: Document IDs {missing_file_document_ids} have no corresponding files in archive", file=sys.stderr)
    extra_file_document_ids = self.file_document_ids - self._unfiltered_document_ids
    if len(extra_file_document_ids) > 0:
      print(f"NOTE: Document IDs {extra_file_document_ids} have files but no item references; they will be ignored", file=sys.stderr)

  def __enter__(self) -> Self:
    return self

  def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None
      ) -> None:
    self.close()

  def close(self) -> None:
    self._zf.close()

  @property
  def zip_file(self) -> ZipFile:
    return self._zf

  @property
  def export_attributes(self) -> JsonableDict:
    if self._export_attributes is None:
      with self._zf.open('export.attributes') as f:
        self._export_attributes = json.load(f)
    return self._export_attributes

  @property
  def export_attributes_zipinfo(self) -> ZipInfo:
    if self._export_attributes_zipinfo is None:
      self._export_attributes_zipinfo = self._zf.getinfo('export.attributes')
    return self._export_attributes_zipinfo

  def get_unfiltered_data(self) -> JsonableDict:
    if self._unfiltered_data is None:
      with self._zf.open('export.data') as f:
        self._unfiltered_data = json.load(f)
    return self._unfiltered_data

  def get_filtered_data(self) -> JsonableDict:
    if self._filtered_data is None:
      result = dict(self.get_unfiltered_data())
      accounts_data: List[JsonableDict] = []
      for account in self.filtered_accounts:
        accounts_data.append(account.filtered_raw_account_data)
      result['accounts'] = accounts_data
      self._filtered_data = result
    return self._filtered_data

  @property
  def export_data_zipinfo(self) -> ZipInfo:
    if self._export_data_zipinfo is None:
      self._export_data_zipinfo = self._zf.getinfo('export.data')
    return self._export_data_zipinfo

  @property
  def files_dir_zipinfo(self) -> ZipInfo:
    if self._files_dir_zipinfo is None:
      try:
        self._files_dir_zipinfo = self._zf.getinfo('files/')
      except KeyError:
        self._files_dir_zipinfo = self.new_zipinfo(
            'files/',
            mode_bits=0o755,
            is_dir=True,
          )
    return self._files_dir_zipinfo

  @property
  def unfiltered_zipinfos(self) -> List[ZipInfo]:
    if self._unfiltered_zipinfos is None:
      result: List[ZipInfo] = []
      seen_filenames: Set[str] = set()
      for zi in self._zf.infolist():
        filename = zi.filename
        if filename in seen_filenames:
          print(f"WARNING: Document file '{filename}' appears multiple times in archive", file=sys.stderr)
        seen_filenames.add(filename)
        if not filename in ('export.attributes', 'export.data', 'files/'):
          if filename.startswith('files/'):
            result.append(zi)
          else:
            print(f"NOTE: 1Password archive contains unexpected file {filename}; it will be ignored", file=sys.stderr)
      self._unfiltered_zipinfos = result
    return self._unfiltered_zipinfos

  @classmethod
  def filename_to_document_id(cls, filename: str) -> str:
    assert filename.startswith('files/')
    if '_' in filename:
      eoid = filename.index('_')
    else:
      eoid = len(filename)
    document_id = filename[6:eoid]
    return document_id

  @property
  def filtered_zipinfos(self) -> List[ZipInfo]:
    if self._filtered_zipinfos is None:
      result: List[ZipInfo] = []
      for zi in self.unfiltered_zipinfos:
        filename = zi.filename
        document_id = self.filename_to_document_id(filename)
        if document_id in self.filtered_document_ids:
          result.append(zi)
      self._filtered_zipinfos = result
    return self._filtered_zipinfos

  @property
  def file_document_ids(self) -> Set[str]:
    if self._file_document_ids is None:
      result: Set[str] = set()
      for zi in self.unfiltered_zipinfos:
        filename = zi.filename
        document_id = self.filename_to_document_id(filename)
        if document_id in result:
          print(f"WARNING: Document ID '{document_id}' associated with multiple files in archive", file=sys.stderr)
        result.add(document_id)
      self._file_document_ids = result
    return self._file_document_ids

  @property
  def unfiltered_accounts(self) -> List[OnePasswordAccountData]:
    return self._unfiltered_accounts

  @property
  def unfiltered_accounts_by_name(self) -> Dict[str, OnePasswordAccountData]:
    return self._unfiltered_accounts_by_name

  @property
  def unfiltered_accounts_by_uuid(self) -> Dict[str, OnePasswordAccountData]:
    return self._unfiltered_accounts_by_uuid

  @property
  def unfiltered_document_ids(self) -> Set[str]:
    return self._unfiltered_document_ids

  @property
  def filtered_accounts(self) -> List[OnePasswordAccountData]:
    return self._filtered_accounts

  @property
  def filtered_accounts_by_name(self) -> Dict[str, OnePasswordAccountData]:
    return self._filtered_accounts_by_name

  @property
  def filtered_accounts_by_uuid(self) -> Dict[str, OnePasswordAccountData]:
    return self._filtered_accounts_by_uuid

  @property
  def filtered_document_ids(self) -> Set[str]:
    return self._filtered_document_ids

  def copy_archive_file(
        self,
        dest_archive: ZipFile,
        filename: str | ZipInfo,
      ) -> None:
    zi = filename if isinstance(filename, ZipInfo) else self._zf.getinfo(filename)
    with self._zf.open(zi, mode='r') as fin:
      with dest_archive.open(zi, mode='w') as fout:
        copyfileobj(fin, fout, self.BUFFER_SIZE)

  def write_archive_json_file(
        self,
        dest_archive: ZipFile,
        filename: str | ZipInfo,
        content: Jsonable,
        copy_zipinfo: bool = True,
      ) -> None:
    zi: ZipInfo
    if isinstance(filename, ZipInfo):
      zi = filename
    elif copy_zipinfo and filename in self._zf.namelist():
      zi = self._zf.getinfo(filename)
    else:
      zi = self.new_zipinfo(filename)
    with dest_archive.open(zi, mode='w') as fout:
      fout.write(json.dumps(content, indent=2, sort_keys=True).encode('utf-8'))

  def write_archive_empty_file(
        self,
        dest_archive: ZipFile,
        filename: str | ZipInfo,
        copy_zipinfo: bool = True,
      ) -> None:
    zi: ZipFile
    if isinstance(filename, ZipInfo):
      zi = filename
    elif copy_zipinfo and filename in self._zf.namelist():
      zi = self._zf.getinfo(filename)
    else:
      zi = self.new_zipinfo(filename)
    with dest_archive.open(zi, mode='w') as fout:
      pass

  def write_archive_directory(
        self,
        dest_archive: ZipFile,
        dirname: str | ZipInfo,
        copy_zipinfo: bool = True,
      ) -> None:
    zi: ZipFile
    if isinstance(dirname, ZipInfo):
      zi = dirname
    else:
      if not dirname.endswith('/'):
        dirname += '/'
      if copy_zipinfo and dirname in self._zf.namelist():
        zi = self._zf.getinfo(dirname)
      else:
        zi = self.new_zipinfo(dirname, is_dir=True)
    with dest_archive.open(zi, mode='w') as fout:
      pass

  def write_filtered_archive(
        self,
        file: StrPath | IO[bytes]
      ) -> None:

    if isinstance(file, str):
      file = open(os.open(file, os.O_CREAT | os.O_WRONLY, 0o600), 'wb')    
    with ZipFile(file, mode='x') as zf:
      zf.debug = 0
      self.copy_archive_file(zf, self.export_attributes_zipinfo)
      self.write_archive_json_file(zf, self.export_data_zipinfo, self.get_filtered_data())
      self.write_archive_directory(zf, self.files_dir_zipinfo)
      for zi in self.filtered_zipinfos:
        self.copy_archive_file(zf, zi)

  @classmethod
  def new_zipinfo(
        cls,
        filename: str,
        mod_time: Optional[datetime.datetime]=None,
        mode_bits: Optional[int]=None,
        is_dir: bool = False,
        is_symlink: bool = False,
        comment: Optional[str]=None
      ) -> ZipInfo:
    if is_symlink:
      is_dir = False

    result = ZipInfo()

    # Specify UTF-8 filename if it includes any extended characters
    if any(ord(c) >= 128 for c in filename):
      result.flag_bits |= 0x0800
    result.filename = filename.encode('utf-8')
    if not mod_time is None:
      result.date_time = mod_time.utctimetuple()[:6]
      posix_timestamp = int(calendar.timegm(mod_time.utctimetuple()))
      # See http://www.opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld
      result.extra += struct.pack('<hhBl', 0x5455, 5, 1, posix_timestamp)

    if mode_bits is None:
      if is_dir:
        mode_bits = 0o755
      else:
        mode_bits = 0o644     

    if is_dir:
      mode_bits |= 0o040000
    elif is_symlink:
      mode_bits |= 0o120000

    external_attr = mode_bits << 16
    if is_dir:
      external_attr |= 0x00000010

    result.external_attr = external_attr
    if is_dir or is_symlink:
      result.compress_type = ZIP_STORED
    else:
      result.compress_type = ZIP_DEFLATED

    if not comment is None:
      result.comment = comment.encode('utf-8')

    return result
