import idautils
import idc

import hashlib

from . import vector


class MnemonicHashVector(vector.Vector):
  type = 'mnemonic_hash'
  type_version = 0

  def data(self):
    if self.inst_count() < 3:
      return None

    md5 = hashlib.md5()
    for ea in idautils.FuncItems(self.offset):
      mnem_line = idc.GetMnem(ea)
      mnem_line = mnem_line.strip()
      mnem_line = mnem_line.lower()
      md5.update(mnem_line)
    return md5.hexdigest()
