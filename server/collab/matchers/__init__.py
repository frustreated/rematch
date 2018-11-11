from .matcher import Matcher
from .hash_matcher import HashMatcher
from .euclidean_matcher import EuclideanDictionaryMatcher
from .instruction_hash import InstructionHashMatcher
from .identity_hash import IdentityHashMatcher
from .assembly_hash import AssemblyHashMatcher
from .mnemonic_hash import MnemonicHashMatcher
from .name_hash import NameHashMatcher
from .mnemonic_euclidean import MnemonicEuclideanMatcher
from .dictionary_matcher import DictionaryMatcher
from .basicblocksize_euclidean import BasicBlockSizeEuclideanMatcher
from .basicblock_mdindex import BasicBlockMDIndexMatcher


matchers_list = [InstructionHashMatcher, IdentityHashMatcher, NameHashMatcher,
                 AssemblyHashMatcher, MnemonicHashMatcher,
                 MnemonicEuclideanMatcher, BasicBlockSizeEuclideanMatcher,
                 BasicBlockMDIndexMatcher]


def matcher_choices():
  return [(m.match_type, m.matcher_name) for m in matchers_list
            if not m.is_abstract()]


__all__ = ['Matcher', 'HashMatcher', 'EuclideanDictionaryMatcher',
           'InstructionHashMatcher', 'IdentityHashMatcher',
           'AssemblyHashMatcher', 'MnemonicHashMatcher', 'NameHashMatcher',
           'MnemonicEuclideanMatcher', 'DictionaryMatcher',
           'BasicBlockSizeEuclideanMatcher', 'BasicBlockMDIndexMatcher',
           'matchers_list']
