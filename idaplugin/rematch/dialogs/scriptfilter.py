import os
import re

from ..idasix import QtWidgets, QtGui

from . import gui
from .. import utils


class SyntaxRule(object):
  def __init__(self, format_name, regex_pattern, *args, **kwargs):
    self.regex = re.compile(regex_pattern.format(*args, **kwargs),
                            re.IGNORECASE)
    self.format_name = format_name

  def match(self, text):
    for match_obj in self.regex.finditer(text):
      index = match_obj.start(1)
      length = match_obj.end(1) - index
      if length:
        yield index, length, self.format_name


class SyntaxFormat(QtGui.QTextCharFormat):
  def __init__(self, color, style='', *args, **kwargs):
    super(SyntaxFormat, self).__init__(*args, **kwargs)

    _color = QtGui.QColor()
    if isinstance(color, str):
      _color.setNamedColor(color)
    else:
      _color.setRgb(*color)
    self.setForeground(_color)

    if 'bold' in style:
      self.setFontWeight(QtGui.QFont.Bold)
    if 'italic' in style:
      self.setFontItalic(True)


class SyntaxHighlighter(QtGui.QSyntaxHighlighter):
  keywords = ['and', 'assert', 'break', 'class', 'continue', 'def', 'del',
              'elif', 'else', 'except', 'exec', 'finally', 'for', 'from',
              'global', 'if', 'import', 'in', 'is', 'lambda', 'not', 'or',
              'pass', 'print', 'raise', 'return', 'try', 'while', 'yield',
              'None', 'True', 'False']

  # Regular-expression escape characters
  operators = ['=', '==', '!=', '<', '<=', '>', '>=', r'\+', '-', r'\*', '/',
               '//', r'\%', r'\*\*', r'\+=', r'-=', r'\*=', r'/=', r'\%=',
               r'\^', r'\|', r'\&', r'\~', '>>', '<<']

  # Regular-expression escape characters
  braces = [r'\{', r'\}', r'\(', r'\)', r'\[', r'\]']

  formats = {'keyword': SyntaxFormat((200, 120, 50), 'bold'),
             'operator': SyntaxFormat((150, 150, 150)),
             'brace': SyntaxFormat('darkGray'),
             'def': SyntaxFormat((220, 220, 255), 'bold'),
             'string': SyntaxFormat((20, 110, 100)),
             'comment': SyntaxFormat((128, 128, 128)),
             'self': SyntaxFormat((150, 85, 140), 'italic'),
             'number': SyntaxFormat((100, 150, 190))}

  def __init__(self, document, *args, **kwargs):
    super(SyntaxHighlighter, self).__init__(document, *args, **kwargs)

    rules = [('self', r'\b(self)\b')]

    # Keywords, operators and brace rules
    rules += [('keyword', r'\b({})\b', kw) for kw in self.keywords]
    rules += [('operator', r'({})', op) for op in self.operators]
    rules += [('brace', r'({})', br) for br in self.braces]

    # Double-quoted strings
    rules += [('string', r'("[^"\\]*(\\.[^"\\]*)*")')]

    # Single-quoted strings
    rules += [('string', r"('[^'\\]*(\\.[^'\\]*)*')")]

    # function and class name definitions
    rules += [('def', r'\bdef\b\s*(\w+):'), ('def', r'\bclass\b\s*(\w+):')]

    # comments
    rules += [('comment', r'(#[^\n]*)')]

    # numbers
    rules += [('number', r'(\b[+-]?[0-9]+[lL]?\b)'),
              ('number', r'(\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b)'),
              ('number',
               r'(\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b)')]

    self.rules = [SyntaxRule(*rule) for rule in rules]

  def highlightBlock(self, text):
    for rule in self.rules:
      for index, length, format_name in rule.match(text):
        self.setFormat(index, length, self.formats[format_name])

      # TODO: multiline string matching


class FilterDialog(gui.GuiDialog):
  def __init__(self, *args, **kwargs):
    super(FilterDialog, self).__init__("Result filter script", *args, **kwargs)

    self.scripts_path = utils.get_plugin_path('scripts')

    self.script_txt = QtWidgets.QPlainTextEdit()
    self.highlighter = SyntaxHighlighter(self.script_txt.document())
    self.statusLbl = QtWidgets.QLabel()
    self.cb = QtWidgets.QComboBox()

    if not os.path.exists(self.scripts_path):
      os.makedirs(self.scripts_path)

    for script_name in os.listdir(self.scripts_path):
      if script_name.endswith(".pyf"):
        self.cb.addItem(script_name)

    if self.cb.count() > 0:
      default_script = os.path.join(self.scripts_path, self.cb.itemText(0))
      with open(default_script, "r") as fh:
        data = fh.read()
        self.script_txt.setPlainText(data)

    self.new_btn = QtWidgets.QPushButton("&New")
    self.save_btn = QtWidgets.QPushButton("&Save")
    self.apply_btn = QtWidgets.QPushButton("&Apply")
    self.cancel_btn = QtWidgets.QPushButton("&Cancel")

    size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed,
                                        QtWidgets.QSizePolicy.Fixed)
    self.new_btn.setSizePolicy(size_policy)
    self.save_btn.setSizePolicy(size_policy)
    self.apply_btn.setSizePolicy(size_policy)
    self.cancel_btn.setSizePolicy(size_policy)

    self.button_layout = QtWidgets.QGridLayout()
    self.button_layout.addWidget(self.new_btn, 0, 0)
    self.button_layout.addWidget(self.save_btn, 0, 1)
    self.button_layout.addWidget(self.apply_btn, 1, 0)
    self.button_layout.addWidget(self.cancel_btn, 1, 1)

    self.apply_btn.clicked.connect(self.validate)
    self.cancel_btn.clicked.connect(self.reject)
    self.save_btn.clicked.connect(self.save_file)
    self.new_btn.clicked.connect(self.new_script)

    self.cb.resize(200, 200)

    help_tooltip = ["While executing the script code, the following context "
                    "variables are available:",
                    "<b>Filter</b>: defaults to False. determines wether "
                    "this item should be filtered out (you should change "
                    "this)",
                    "<b>Errors</b>: defaults to 'stop'. when a runtime "
                    "error occures in script code this will help determine "
                    "how to continue.",
                    "There are several valid values:",
                    " - '<b>stop</b>': handle runtime errors as ",
                    "non-continual. stop using filters immidiately.",
                    " - '<b>filter</b>': filter this function using whatever "
                    "value was in Filter at the time of the error",
                    " - '<b>hide</b>': hide all functions in which a "
                    "filtering error occured, after displaying a warning.",
                    " - '<b>show</b>': show all functions in which a "
                    "filtering error occured, after displaying a warning.",
                    "",
                    "When filtering a match function(a leaf) both the local "
                    "and match variables exist.",
                    "When filtering a local function(a tree root) only the "
                    "local variable exist, and remote equals to None.",
                    "The local variable describes the local function (tree "
                    "root), and the match variable describes the function "
                    "matched to the local one(the local root's leaf).",
                    "both the local and match variables, if exist, are "
                    "dictionaries containing these keys:",
                    "<b>'ea'</b>: effective address of function",
                    "<b>'name'</b>: name of function (or a string of ea in "
                    "hexadecimal if no name defined for match functions)",
                    "<b>'docscore'</b>: a float between 0 and 1.0 "
                    "representing the documentation score of function",
                    "<b>'score'</b>: (INTERNAL) a float between 0 and 1.0 "
                    "representing the match score of this function and the "
                    "core element",
                    "<b>'key'</b>: (INTERNAL) the match type.",
                    "<b>'documentation'</b>: (INTERNAL) available "
                    "documentation for each line of code",
                    "<b>'local'</b> : True if this function originated from "
                    "the local binary (for when a local function matched "
                    "another local function).",
                    "",
                    "Note: variables marked as INTERNAL are likely to change "
                    "in format, content and values without prior notice. your "
                    "code may break.",
                    "user discretion is advised."]
    help_tooltip = "\n".join(help_tooltip)

    self.help_lbl = QtWidgets.QLabel("Insert native python code to filter "
                                     "matches:\n(Hover for more information)")
    self.help_lbl.setToolTip(help_tooltip)

    self.combo_layout = QtWidgets.QHBoxLayout()
    self.combo_layout.addWidget(QtWidgets.QLabel("Script - "))
    self.combo_layout.addWidget(self.cb)

    self.base_layout.addWidget(self.help_lbl)
    self.base_layout.addLayout(self.combo_layout)
    self.base_layout.addWidget(self.script_txt)
    self.base_layout.addWidget(self.statusLbl)
    self.base_layout.addLayout(self.button_layout)

    self.cb.currentTextChanged.connect(self.combobox_change)

  def save_file(self):
    current_file = self.cb.currentText()
    fpath, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Data File",
                                                     self.scripts_path,
                                                     "Python filter (*.pyf)")
    if not fpath:
      return

    with open(fpath, 'w') as fh:
      fh.write(self.script_txt.toPlainText())

    self.cb.clear()
    for file in os.listdir(self.scripts_path):
      if file.endswith(".pyf"):
        self.cb.addItem(file)
    self.cb.setCurrentText(current_file)

  def new_script(self):
    if not self.cb.itemText(0) == "New":
      self.cb.insertItem(0, "New")
      self.cb.setCurrentIndex(0)

  def combobox_change(self, new_value):
    fpath = os.path.join(self.scripts_path, new_value)
    if os.path.isfile(fpath):
      with open(fpath, "r") as myfile:
        data = myfile.read()
    else:
      data = ""
    self.script_txt.setPlainText(data)

  def get_code(self):
    return self.script_txt.toPlainText()

  def validate(self):
    try:
      compile(self.get_code(), '<input>', 'exec')
      # TODO: get code to actually run on data before accept()ing so validation
      # will be more percise
    except Exception as ex:
      import traceback
      self.exception_base(ex, traceback.format_exc())
    else:
      self.set_status("")
      self.accept()
