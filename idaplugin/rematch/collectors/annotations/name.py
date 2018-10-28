import ida_name

from . import annotation


class NameAnnotation(annotation.Annotation):
  type = 'name'

  def data(self):
    name = ida_name.get_name(self.offset)
    if ida_name.is_uname(name):
      # TODO: get flags here
      return {'name': name, 'flags': 0}
    return None

  def apply(self, data):
    name = str(data['name'])
    # TODO: flags should be abstructed away from thier enum values to support
    # changes between versions
    flags = data['flags']
    ida_name.set_name(self.offset, name, flags)
