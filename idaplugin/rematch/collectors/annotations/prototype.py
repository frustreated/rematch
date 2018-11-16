import ida_typeinf
import idc

from ... import log
from . import annotation


class PrototypeAnnotation(annotation.Annotation):
  type = 'prototype'

  def data(self):
    # get function type info
    ti = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(ti, self.offset)

    # skip it if it's empty
    if ti.empty():
      return None

    t = ida_typeinf.idc_get_type(self.offset)
    # if failed getting type, there's no annotation here
    if t is None:
      return None

    # if type equals guessed type, no need to save annotation
    if t == ida_typeinf.idc_guess_type(self.offset):
      return None

    return {'prototype': t}

  def apply(self, data):
    prototype = data['prototype']
    if idc.SetType(self.offset, prototype) is None:
      log('annotation_prototype').warn("Setting prototype failed at %s with "
                                       "%s", self.offset, data)
