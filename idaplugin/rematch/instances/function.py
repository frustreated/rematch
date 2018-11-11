from . import base
from .. import collectors

import idautils


class EmptyFunctionInstance(base.BaseInstance):
  type = 'empty_function'

  def __init__(self, *args, **kwargs):
    super(EmptyFunctionInstance, self).__init__(*args, **kwargs)
    self.annotations |= {collectors.annotations.PrototypeAnnotation}


class FunctionInstance(EmptyFunctionInstance):
  type = 'function'

  def __init__(self, *args, **kwargs):
    super(FunctionInstance, self).__init__(*args, **kwargs)
    self.vectors |= {collectors.vectors.InstructionHashVector,
                     collectors.vectors.IdentityHashVector,
                     collectors.vectors.AssemblyHashVector,
                     collectors.vectors.MnemonicHashVector,
                     collectors.vectors.MnemonicHistVector,
                     collectors.vectors.BasicBlockSizeHistVector,
                     collectors.vectors.BasicBlockAdjacencyVector}
    self.annotations |= {collectors.annotations.AssemblyAnnotation}

  def size(self):
    """return the overall size of function by adding sizes of all individual
    chunks"""
    return sum([chunk[1] - chunk[0] for chunk in idautils.Chunks(self.offset)])

  def count(self):
    """return the number of instructions contained in function"""
    return len(list(idautils.FuncItems(self.offset)))
