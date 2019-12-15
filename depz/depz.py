#!/usr/bin/env python3


# Necessary keys:
# full_directory
# type (not actually currently used)
# checkout
# checkout_remote - list of remotes to try

# Other keys
# skip - Skip archive altogether
# update_skip - Don't try to update
# fast_forward_skip - Don't try to fast forward
# monitor_branch=br1,br2,br3 # Local branches to check for updates and FF
# no_tags - don't fetch tags
# init_archive - Initialize from an archive file
# init_archive_sha1 - Check hash of init_archive
# init_archive_sha256 - Check hash of init_archive
# init_archive_sha512 - Check hash of init_archive



from configparser import SafeConfigParser as ConfigParser
from configparser import ExtendedInterpolation
from io import StringIO

import sys
import os



NO_DEFAULT = object()

class ConfigProxy (object):
  def __init__ (self, config, section, default=NO_DEFAULT):
    self._config = config
    self._section = section
    self._default = default

  def __getattr__ (self, attr):
    return self._config.get(self._section, attr, default=self._default)


class Section (object):
  def __init__ (self, config, section, default=NO_DEFAULT):
    self._config = config
    self._section = section
    self._default = default
    self._dict = None
    self._props = None

  def __contains__ (self, attr):
    try:
      self._config.get(self._section, attr)
      return True
    except Exception:
      return False

  @property
  def val (self):
    if self._props is None:
      self._props = ConfigProxy(self._config, self._section, self._default)
    return self._props

  def __getattr__ (self, attr):
    return self._config.get(self._section, attr, default=None)

  def __index__ (self, index):
    self.items()
    return self.items()[index]

  def __len__ (self):
    return len(self.items())

  @property
  def dict (self):
    if self._dict is not None: return self._dict
    o = {}
    self._dict = o
    for k in self._config.section_keys(self._section):
      try:
        o[k] = self._config.get(self._section, k)
      except Exception as e:
        #print(e)
        pass
    return o

  def items (self):
    return self.dict.items()

  def keys (self):
    return self.dict.keys()

  def get (self, *args, **kw):
    return self.dict.get(*args, **kw)

  def get_bool (self, key, default=False):
    return _to_bool(self.get(key, default))


def _to_bool (v):
  v = str(v).lower()
  return v in "yes true on 1 enable enabled ok okay +".split()


"""
[foo]
# This is a section called foo.
# If there are other foo sections in other files, the values from the earlier
# files take precedence.
bar=42

[DEFAULT foo]
# Values in here will show up when reading foo if no other foo section has
# actually included them.
bar=100 # bar already defined; this has no effect
baz=spam # shows up when looking at foo.baz

[OVERRIDE foo]
# Values in here will override values in foo.
# If there are "OVERRIDE foo" sections in later files, their values take
# precedence.
bar=1 # foo.bar==1

[foo foobie]
# This is a "foo" section called "foobie".  When accessing foobie, values from
# foo will act as defaults.
"""

class Config (object):
  NO_DEFAULT = NO_DEFAULT
  COMMANDS = set("DEFAULT OVERRIDE TRY-INCLUDE INCLUDE".split())

  @staticmethod
  def _newcp (*args, **kw):
    #return ConfigParser(*args, strict=False, **kw)
    cp = ConfigParser(*args, strict=False,
                      interpolation=ExtendedInterpolation(),
                      default_section=" ILLEGAL SECTION ", **kw)
    cp.optionxform = str
    return cp

  def __init__ (self, extensions=[]):
    self._files = []
    self._files_ignore_errors = [] # 1:1 with _files
    # There is one dumb case with the above.  If a raw string has been injected via
    # .include_string(), it shows up in _files as None and _f_i_e as the string.

    self._defined_sections = []
    self._cp = None
    self._real_sections = None
    ##self._base_defaults = {}
    ##self._base_defaults_with_files = {} #k->(filenum,value)
    self._final = {}
    self._globals = {}
    self._globals_with_files = {}
    # Is there a point in storing a filenum instead of the filename?
    self._section_files = {} # sectionname->[files with that section]
    if isinstance(extensions, str): extensions = extensions.split()
    self.extensions = [e.lstrip(".") for e in extensions]

  def _init (self):
    if self._cp is not None:
      self._cp._sections = self._real_sections
      self._cp.defaults().clear()
      return self._cp

    defaults = []
    defaults_with_files = []
    all_skvs = []
    for num,(fn,ie) in enumerate(zip(self._files, self._files_ignore_errors)):
      cp = self._newcp()
      if fn is None:
        cp.readfp(StringIO(ie)) #HACK
      elif ie:
        cp.read(fn)
      else:
        cp.readfp(open(fn))
      assert not cp.defaults(), "This section not allowed"
      defaults.append(cp.defaults().copy())
      defaults_with_files.append({k:(num,v) for k,v in cp.defaults().items()})
      cp.defaults().clear()
      skvs = {}
      for s in cp.sections():
        if s not in self._section_files: self._section_files[s] = []
        self._section_files[s].append(fn)
        these_kvs = {}
        skvs[s] = these_kvs
        for k,v in cp.items(s, raw=True):
          these_kvs[k] = (num,v)
      all_skvs.append(skvs)

    # Store the global defaults.  I'm not even sure we really care about
    # these, since we have our special GLOBALS section, but sure, whatever.
    # We do it backwards so that earlier files trump later files.
    ##for d,dwf in zip(defaults, defaults_with_files):
    ##  self._base_defaults.update(d)
    ##  self._base_defaults_with_files.update(dwf)

    final = {}
    override = {}

    # Two things on this pass:
    # 1) Just gather all the section names and make empty sections
    # 2) Build a dictionary of overrides where values from later
    #    files take precedence over earlier files.
    for fn,cskvs in zip(self._files, all_skvs):
      for section,kvs in cskvs.items():
        if section not in final: final[section] = {}
        if section not in override: override[section] = {}
        override[section].update(kvs.items())

    # Go through in reverse order so that values from earlier files take
    # precdence over values in later files
    reverse_order = reversed(list(zip(self._files, all_skvs)))
    for fn,cskvs in reverse_order:
      for section,kvs in cskvs.items():
        final[section].update(kvs)

    # Grab list of sections that were actually defined (not filled in via
    # defaults or whatever).
    self._defined_sections = list(final.keys())

    # Apply defaults.  Since we're using them as gathered in the previous
    # step, DEFAULT sections in earlier files take precedence, but the
    # eventual defaults will never override given values.
    for section,kvs in list(final.items()):
      section = section.split(None,1)
      if len(section) != 2 or section[0] != "DEFAULT": continue
      section = section[1]
      if section not in final:
        final[section] = kvs.copy()
      else:
        final[section] = dict(list(kvs.items()) + list(final[section].items()))

    # Now apply parent values (from "PARENT") to individual child sections
    # ("PARENT child").  Again, values from PARENTS in earlier sections take
    # precedence, but values existing in children take precdence over those.
    # This also pulls overrides from the parent into the child.
    for section,kvs in final.items():
      parent = section.split(None,1)
      if len(parent) != 2 or parent[0] in self.COMMANDS: continue
      parent = parent[0]
      p = final.get(parent, {})
      final[section] = dict(list(final[parent].items()) + list(kvs.items()))
      o = override.get("OVERRIDE " + parent, {}) # Don't love this
      final[section].update(o)

    # Apply overrides.  Child "PARENT child" already got overrides from
    # "OVERRIDE PARENT", so this just needs for section "foo" to get its
    # direct overrides ("OVERRIDE foo").  Where foo might itself be a
    # child (that is, we handle "OVERRIDE PARENT child" here).  But note
    # that this isn't all beautifully recursive.
    for section,kvs in override.items():
      over = section.split(None,1)
      if len(over) != 2 or over[0] != "OVERRIDE": continue
      over = over[1]
      #? if over not in final: continue
      if over not in final: final[over] = {}
      final[over].update(kvs)

    # Postprocess
    for section,kvs in final.items():
      for k,(filename,v) in kvs.items():
        vv = self.entry_hook(section, k, v, filename)
        if v != vv: kvs[k] = (filename,vv)

    # Copy into an actual CP
    cp = self._newcp()
    self._cp = cp
    for section,kvs in final.items():
      cp.add_section(section)
      for k,v in kvs.items():
        cp.set(section, k, v[1])

    self._cp = cp
    self._final = final
    self._globals_with_files = final.get("GLOBALS", {})
    self._globals = {k:v[1] for k,v in self._globals_with_files.items()}
    self._real_sections = cp._sections

    return cp

  def entry_hook (self, section, key, value, filename):
    return value

  def include_string (self, string):
    self._files.append(None)
    self._files_ignore_errors.append(string)

  def try_include_files (self, *files):
    return self.include_files(*files, ignore_errors=True)

  def include_files (self, *files, **kw):
    ignore_errors = kw.pop("ignore_errors", False)
    assert not kw
    change = False
    next_files = []
    for w in files:
      w = os.path.realpath(w)
      if not os.path.isfile(w):
        if self.extensions and not os.path.splitext(w)[1]:
          for ext in self.extensions:
            if os.path.isfile(w + "." + ext):
              w += "." + ext
              break
      d,f = os.path.split(w)
      if w in self._files: continue
      change = True
      self._files.append(w)
      self._files_ignore_errors.append(ignore_errors)
      cp = self._newcp()
      if ignore_errors:
        cp.read(w)
      else:
        cp.readfp(open(w))
      for s in cp.sections():
        st = s.split(None, 1)
        if len(st) != 2: continue
        if st[0] == "INCLUDE" or st[0] == "TRY-INCLUDE":
          inc = st[1]
          if not os.path.isabs(inc):
            inc = os.path.join(d, inc)
          #if self.include_files(inc, ignore_errors = st[0] == "TRY-INCLUDE"):
          #  change = True
          # Do breadth first instead:
          next_files.append((inc, st[0] == "TRY-INCLUDE"))
    for w,ie in next_files:
      if self.include_files(w, ignore_errors=ie):
        change = True
    return change

  def has_section (self, section):
    """
    Checks is a section exists

    Note that this will return False for a section "foo" if "OVERRIDE foo"
    exists but "foo" itself does not.
    """
    return self._init().has_section(section)

  def sections (self, strict=False):
    cp = self._init()
    r = set()
    for sec in cp.sections():
      ss = sec.split(None, 1)
      if len(ss) == 2:
        if ss[0] == "DEFAULT" or ss[0] == "OVERRIDE":
          if strict: continue
          sec = ss[1]
        elif ss[0] in self.COMMANDS:
          continue
      r.add(sec)
    return sorted(r)

  def section_keys (self, section):
    """
    Get the keys in a section

    If the section does not exist, it just returns an empty list.
    """
    self._init()
    cp = self._cp

    keys = set()
    try:
      keys.update(k for k,v in cp.items(section, raw=True))
    except Exception:
      pass
    return sorted(keys)

  @staticmethod
  def _get_raw_items (cp, section):
    if not cp.has_section(section): return {}
    return dict(cp.items(section))

  def get_section (self, section, default=NO_DEFAULT):
    return Section(self, section, default=default)

  def __index__ (self, section):
    return self.get_section(section)

  def get (self, section, option, raw=False, default=NO_DEFAULT, global_vars=True):
    cp = self._init()
    assert section != "DEFAULT"
    cpd = cp.defaults()
    #if default is not self.NO_DEFAULT: cpd[option] = default
    #cpd.update(self._base_defaults)

    if global_vars:
      cpd.update(self._globals)

    overrides = {"_FULL_NAME_": section,
                 "_NAME_": section.split(None,1)[-1],
                 "_KEY_": option}

    filename = None
    if section in self._final and option in self._final[section]:
      filename = self._files[self._final[section][option][0]]
    elif option in self._globals:
      filename = self._files[self._globals_with_files[option][0]]
    if filename is not None:
      overrides["_FILE_"] = filename
      overrides["_DIR_"] = os.path.dirname(filename)
    if section in self._section_files:
      secfile = [x for x in self._section_files[section] if x is not None]
      if secfile:
        secfile = secfile[0]
        overrides["_SECTION_FILE_"] = secfile
        overrides["_SECTION_DIR_"] = os.path.dirname(secfile)

    #self._cp._sections = self._cp._sections.copy()
    #if section not in self._cp._sections: self._cp._sections[section] = {}
    #self._cp._sections[section].update(overrides)
    #self._cp._defaults.update(overrides)
    cpd.update(overrides)

    return self._cp.get(section, option, raw=raw)


class ChDir (object):
  def __init__ (self, directory):
    self.previous = os.getcwd()
    self.current = directory

  def __enter__ (self):
    os.chdir(self.current)

  def __exit__ (self, type, value, traceback):
    assert os.getcwd() == self.current, "The working directory changed"
    os.chdir(self.previous)


import urllib.request
import shutil
import tempfile
import os
import hashlib
import datetime

def get_archive (url, dst, denest=True, sha1=None, sha256=None, sha512=None):
  """
  Download an archive at 'url' into directory 'dst'.

  'dst' needs to be empty with the sole except that it can contain an entry
  named ".git".

  An entry at the top of the archive named ".git" will be ignored.

  It's often the case that an archive contains a single top-level item -- a
  directory that contains the rest of the contents.  If 'denest' is True (the
  default), the top level directory will be ignored and its *contents* will be
  put into 'dst'.
  """
  denest_dir = None
  final_url = None
  timestamp = None # ~ Latest modification time

  if not os.path.isdir(dst):
    raise RuntimeError("Destination directory '%s' does not exist" % (dst,))
  dst_listing = os.listdir(dst)
  if dst_listing:
    if len(dst_listing) == 1 and dst_listing[0] == ".git":
      pass # Okay
    else:
      raise RuntimeError("Destination directory not empty")

  with tempfile.NamedTemporaryFile() as temp_file:
    with urllib.request.urlopen(url) as response:
      shutil.copyfileobj(response, temp_file)
      final_url = response.geturl()

      hashers = []
      if sha1: hashers.append((hashlib.sha1(),sha1))
      if sha256: hashers.append((hashlib.sha256(),sha256))
      if sha512: hashers.append((hashlib.sha512(),sha512))
      if hashers:
        with open(temp_file.name, 'rb') as check_file:
          while True:
            data = check_file.read(1024*64)
            if not data: break
            for h,_ in hashers:
              h.update(data)
        for h,good_hash in hashers:
          if h.hexdigest().lower() != good_hash.lower():
            raise RuntimeError("Hash did not match")

    def find_format (extmatch):
      for fmt,exts,_ in shutil.get_unpack_formats():
        for ext in exts:
          if extmatch.endswith(ext.lower()):
            return fmt
      return None

    fmt = find_format(url.lower())
    if not fmt:
      if final_url:
        fmt = find_format(final_url.lower())
      if not fmt:
        raise RuntimeError("Can't determine archive type for '%s'" % (url,))

    with tempfile.TemporaryDirectory() as temp_dir:
      assert not os.listdir(temp_dir)
      shutil.unpack_archive(temp_file.name, temp_dir, fmt)

      listing = os.listdir(temp_dir)
      if not listing:
        raise RuntimeError("Archive seems to be empty")

      src = temp_dir
      if denest and len(listing) == 1:
        nest_dir = os.path.join(temp_dir, listing[0])
        if os.path.isdir(nest_dir):
          src = nest_dir
          denest_dir = listing[0]

      for src_element in os.listdir(src):
        if src_element == ".git": continue
        full_src_element = os.path.join(src, src_element)
        full_dst_element = os.path.join(dst, src_element)
        if os.path.isdir(full_src_element):
          shutil.copytree(full_src_element, full_dst_element)
        elif os.path.islink(full_src_element):
          pass # Just ignore (for now?)
        else:
          shutil.copy2(full_src_element, full_dst_element)

      files = glob.glob(os.path.join(temp_dir, '**'), recursive=True)
      for f in files:
        if os.path.join(f,'') == os.path.join(temp_dir,''): continue
        t = os.stat(f).st_mtime
        if timestamp is None or t > timestamp:
          timestamp = t

  dt = None
  if timestamp is not None:
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    dt = epoch + datetime.timedelta(seconds=timestamp)
  return (denest_dir,final_url or url,timestamp,dt)


class SimpleError (RuntimeError):
  pass


DEFAULT_REPO = """

[DEFAULT REPO]
name=${_NAME_}
remote_name=${name}
checkout=master
checkout_remote=mine,origin,upstream
type=git
remote origin=${prefix}/${remote_name}
base_directory=${_SECTION_DIR_}
full_directory=${base_directory}/${directory}
directory=${name}
group=default

"""


def strsplit (s, *args, **kw):
  """
  Like str.split(), but empty string gives empty list
  """
  if not s: return []
  return s.split(*args, **kw)


import logging
log_is_tty = False
SPAM = 5

cur_log_level = logging.INFO
def set_log_level (level):
  if isinstance(level, str):
    if level.upper() == "SPAM":
      level = SPAM
    else:
      level = getattr(logging, level.upper())
  global cur_log_level
  cur_log_level = level
  _set_log_level(level)


def init_config ():
  global _set_log_level
  _set_log_level = log.setLevel

  config = Config()
  config.try_include_files(os.path.expanduser("~/.depzconfig"))
  config._init()
  try:
    config._cp.add_section("depz")
  except Exception:
    pass
  config = config._cp

  # It'd be nice if this used Config() more normally, but this is pretty hacky

  cl = config["depz"].get("color_log", None)
  if cl is not None and _to_bool(cl):
    try:
      import coloredlogs
      try:
        def_ln = coloredlogs.DEFAULT_FIELD_STYLES['levelname']
        if def_ln['color'] == 'black':
          def_ln['bright'] = True
      except Exception as e:
        pass
      coloredlogs.DEFAULT_LOG_FORMAT = ('%(levelname)-8s %(asctime)s '
                                        '%(name)-20s %(message)s')
      coloredlogs.DEFAULT_DATE_FORMAT = '%H:%M:%S'
      coloredlogs.install()
      coloredlogs.set_level(logging.DEBUG)
      _set_log_level = coloredlogs.set_level
    except Exception:
      pass

  ll = config["depz"].get("log_level", None)
  if ll is not None:
    set_log_level(ll)


import argparse

def main ():
  global log
  global args
  global log_is_tty
  log_is_tty = sys.stderr.isatty()

  logging.basicConfig(level=logging.DEBUG,format="%(levelname)-8s %(name)-20s %(message)s")
  log = logging.getLogger("depz")

  init_config()

  p = argparse.ArgumentParser(description="Manage subproject repositories.")
  p.add_argument("-r", "--depz", default=["."], action='append',
      help="Path to a .depz file or a directory containing .depz files.")
#  p.add_argument("--yes",
#      help="Automatically answer Yes to questions (dangerous!).")
  p.add_argument("--init", action='store_true',
      help="Initialize the repositories.")
  p.add_argument("-L", "--log-level", "--ll", default="info",
      choices="debug info warn error".split(),
      help="Set the log level.")
  p.add_argument("--name", default="*",
      help="Name or names of repos to operate on.")
  p.add_argument("--group", #default="default",
      help="Group or groups of repos to operate on.  (Default is 'default'.)")
  p.add_argument("--dump", nargs="?", default=[], action='append',
      choices="early late all".split(),
      help="Show the list of repos and their properties.  Normally this is done "
           "'early' -- before sanity checking.  It can also be done 'late'.  "
           "If 'all', dump before even doing filtering.")
  p.add_argument("--update", action="store_true",
      help="Update remotes.")
  p.add_argument("--outdated", action="store_true",
     help="Show possibly outdated repositories.")
  p.add_argument("--fast-forward", "--ff", action="store_true",
     help="Fast forward merge repositories.")
  p.add_argument("--set-ssh-cmd", action="store_true",
     help="Set the default ssh command for the repository to use a deploy "
          "key (git 2.10 and above).")
  p.add_argument("--force-deploy-keys", type=bool,
     const=False, default=None, nargs='?',
     help="Can be true (default) or false.  Attempts to force using or not "
          "using deploy keys.  Be careful.")
  p.add_argument("--set", "-S", nargs="*", action='append', default=[],
     help="Set a config value, e.g., '--set [section]key=value'.")


  args = p.parse_args()

  set_log_level(args.log_level)

  app = App()



def filter_groups (all_repos, filter_string):
  filters = filter_string.replace(","," ").split()
  nofilter = [f[1:] for f in filters if f.startswith("-")]
  yesfilter = [f for f in filters if not f.startswith("-")]

  # Must match at least one yesfilter and no nofilter
  def does_match (groups, filters):
    for f in filters:
      for g in groups:
        if wildmatch(g, f): return True
    return False

  remove = set()
  for r,rr in all_repos.items():
    groups = rr.val.group.replace(","," ").split()
    if not does_match(groups, yesfilter):
      remove.add(r)
    #elif does_match(groups, nofilter):
    #  remove.add(r)

  for r in remove: del all_repos[r]


def match_names (all_repos, name_string):
  names = set(name_string.replace(","," ").split())
  keep = []
  for r in all_repos:
    for n in names:
      if wildmatch(r, n):
        keep.append(r)
        break
  return keep


import glob
from fnmatch import fnmatchcase as wildmatch
from collections import OrderedDict
import re
is_hex = re.compile("^[0-9a-fA-F]+$").match

FINISH_PRIORITY = 99999999

class App (object):
  def __init__ (self):
    config = Config(extensions=["depz", "depzconfig"])
    #config.entry_hook = _directory_hook

    config.try_include_files(os.path.expanduser("~/.depzconfig"))

    commandline_section = ""
    for set_args in args.set:
      # This is sort of goofy, but it lets us handle what come across as two
      # distinct cases:
      #  * depz --set=[s1]k1=v1 --set=[s2]k2=v2
      #  * depz --set [s1]k1=v1 [s2]k2=v2
      if not isinstance(set_args, list): set_args = [set_args]
      for set_arg in set_args:
        if not set_arg.startswith("["):
          raise RuntimeError("Expected --set argument to start with '['")
        if not ']' in set_arg:
          raise RuntimeError("Expected --set argument to start with '['")
        set_arg = set_arg.replace("]", "]\n")
        commandline_section += set_arg + "\n"
    if commandline_section:
      config.include_string(commandline_section)

    config.include_string(DEFAULT_REPO)

    if len(args.depz) > 1: del args.depz[0]

    for repo in args.depz:
      if os.path.isdir(repo):
        files = glob.glob(os.path.join(repo, "*.depz"))
        log.debug("Adding %s (%s)", repo, App.pluralize(len(files),"file"))
        config.include_files(*files)
      else:
        log.debug("Adding %s", repo)
        config.include_files(repo)

    all_repos = OrderedDict()
    for secname in config.sections(strict=True):
      parts = secname.split(None,1)
      if not len(parts) == 2: continue
      if parts[0] != "REPO": continue
      if not parts[1]: continue
      all_repos[parts[1]] = config.get_section(secname)

    self.args = args
    self.all_repos = all_repos

    self.done_commands = []
    self.commands = {}

    self.error_repos = set()

    if 'all' in args.dump:
      self.for_each_repo(self.do_dump, first=[True])()

    # Okay, the filtering has gone through some changes.  The way it works now
    # is that if you specify a name but no group, it'll match name regardless
    # of group.  Otherwise, it defaults to group "default".
    #filter_bad(all_repos, config)
    #full_list = all_repos.copy()
    matched_names = match_names(all_repos, args.name)
    for r in list(all_repos.keys()):
      if r not in matched_names: del all_repos[r]
    if args.name != "*" and args.group is None:
      args.group = "*"
    elif args.group is None:
      args.group = "default"
    filter_groups(all_repos, args.group)

    # Always include a specific name
    #for m in matched_names:
    #  if m not in all_repos: all_repos[m] = full_list[m]

    if 'early' in args.dump or None in args.dump:
      self.add_command(self.for_each_repo(self.do_dump, first=[True]))
    self.add_command(self.for_each_repo(self.do_early_sanity_check))
    if args.init: self.add_command(self.for_each_repo(self.do_init))
    self.add_command(self.for_each_repo(self.do_sanity_check))
    if args.set_ssh_cmd:
      self.add_command(self.for_each_repo(self.do_set_ssh_cmd))

    if 'late' in args.dump:
      self.add_command(self.for_each_repo(self.do_dump, first=[True]))
    if args.update:
      self.add_command(self.for_each_repo(self.do_update))
    if args.outdated:
      self.add_command(self.for_each_repo(self.do_show_outdated))
    if args.fast_forward:
      self.add_command(self.for_each_repo(self.do_fast_forward))

    self.run_commands()

  def run_commands (self):
    while True:
      c = self.pop_command()
      if c is None: break
      c()

  def add_error_repo (self, r):
    self.error_repos.add(r)

  def pop_command (self):
    priorities = sorted(self.commands.keys())
    for p in priorities:
      if len(self.commands[p]):
        c = self.commands[p].pop(0)
        self.done_commands.append(c)
        return c
    return None

  def add_command (self, c, priority=0):
    if priority > FINISH_PRIORITY:
      raise RuntimeError("Command priority too high")
    if priority not in self.commands:
      self.commands[priority] = []
    self.commands[priority].append(c)

  @staticmethod
  def _get_conf_remotes (rr):
    remotes = {k.split(None,1)[1]:v for k,v in rr.items()
               if k.split(None,1)[0] == "remote"}
    return remotes

  @staticmethod
  def _get_conf_remote_uses_deploy_key (rr, remote):
    if args.force_deploy_keys is not None:
      return args.force_deploy_keys
    dks = {k.split(None,1)[1]:v for k,v in rr.items()
           if k.split(None,1)[0] == "deploy_key"}
    dk = dks.get(remote)
    if dk is None: return False
    if _to_bool(dk): return True
    if os.path.isfile(dk+".pub") and os.path.isfile(dk+".private"): return dk
    return False

  def for_each_repo (self, f, **kw):
    funcname = getattr(f, "__name__", "")
    if funcname.startswith("do_"):
      funcname = funcname[3:]
    else:
      funcname = None
    def for_each_func ():
      if funcname: log.debug("Running function %s", funcname)
      for i,(rname,rr) in enumerate(self.all_repos.items()):
        if rname in self.error_repos: continue
        try:
          f(rname,rr, **kw)
        except SimpleError as e:
          log.error("Error processing %s: %s" % (rname, e))
          self.add_error_repo(rname)
        except Exception:
          log.exception("While processing %s:" % (rname,))
          self.add_error_repo(rname)
    return for_each_func

  def do_dump (self, rname, rr, first):
    if first[0] != True:
      print()
    first[0] = False
    print("[%s]" % (rname,))
    for k,v in sorted(list(rr.items())):
      print("%s=%s" % (k,v))

  @classmethod
  def _get_ssh_cmd (cls, git, rname, rr, rem):
    if not cls._get_conf_remote_uses_deploy_key(rr, rem): return None
    if not git.has_deploy_key(rem): return None

    keyfile_base = os.path.join(git.path, "depz_deploy_key")
    keyfile_base += "." + rem.replace(" ","-")
    if '"' in keyfile_base or '$' in keyfile_base:
      log.getChild(rname).error("Can't set ssh command because path looks funny")
      return None
    cmd = 'ssh -i "%s.private" -F /dev/null' % (keyfile_base,)
    return cmd

  def do_set_ssh_cmd (self, rname, rr):
    git = Git(rr.val.full_directory)

    for remote in git.remotes.keys():
      newsshcmd = self._get_ssh_cmd(git, rname, rr, remote)
      if not newsshcmd: continue

      sshcmd = git.conf.get("core.sshCommand")
      if sshcmd and sshcmd != newsshcmd:
        llog.warn("ssh command is already set; not resetting")
        return False
      elif not sshcmd:
        git.conf["core.sshCommand"] = newsshcmd
        llog.info("Set SSH command to use deploy key for %s", remote)
        return True
      else:
        llog.debug("SSH command already using deploy key")
        return True

    return False

  def _gen_deploy_key (self, git, rname, rr, remote, url=None):
    llog = log.getChild(rname)
    git.check_toplevel()

    if url is None:
      url = git.remotes.get(remote, None)
      if url is None:
        url = self._get_conf_remotes(rr).get(remote, None)
        if url is None:
          raise SimpleError("Unknown remote '%s'" % (remote,))

    if url.startswith("git@") or url.startswith("ssh:"):
      # This is pretty bad ssh URL detection...
      pass
    else:
      llog.warn("Not generating deploy key for non-ssh remote")
      return False

    created = False

    keyfile_base = git.get_keyfile_base(remote)
    if (os.path.exists(keyfile_base) or os.path.exists(keyfile_base+".pub")
        or os.path.exists(keyfile_base+".private")):
      # Something exists... is it the right stuff?
      if (os.path.exists(keyfile_base+".private")
          and os.path.exists(keyfile_base+".pub")
          and not os.path.exists(keyfile_base)):
        llog.debug("%s files look good", keyfile_base)
      else:
        raise SimpleError(keyfile_base + " files seem misconfigured")
    else:
      keyname = ("depz_deploy_key_%s_%s" % (rname, remote)).replace(" ", "-")
      cmd = ["ssh-keygen","-t","rsa","-b","4096","-N","","-q","-C",keyname]
      cmd += ["-f",keyfile_base]

      r = subprocess.run(cmd, check=False)
      if r.returncode != 0:
        llog.error("Key generation failed")

      if os.path.exists(keyfile_base) and os.path.exists(keyfile_base+".pub"):
        llog.debug("Key files created")
      else:
        raise SimpleError("Key files not created")

      os.rename(keyfile_base, keyfile_base + ".private")

      created = True

    excludes = open(os.path.join(git.path,".git/info/exclude"), "r").read()
    excludes = excludes.split("\n")
    exclude_entry = "**/depz_deploy_key.*"
    if exclude_entry not in excludes:
      with open(os.path.join(git.path,".git/info/exclude"), "a") as ef:
        ef.write(exclude_entry + "\n")
      llog.info("Added %s to git excludes", exclude_entry)
    else:
      llog.debug("Exclude entry %s already in git excludes", exclude_entry)

    # Take a guess at the remote (truly bad)
    def get_desc (r):
      url = None
      if r.startswith("git@github.com:"):
        url = "https://github.com/" + r.split(":",1)[1]
      elif r.startswith("ssh://") and "github.com/" in r:
        url = "https://github.com/" + r.split("/",3)[3]

      r = "%s remote %s" % (rname, remote)
      if url:
        url = url.rstrip("/")
        if url.endswith(".git"): url = url[:-4]
        url += "/settings/keys/new"
        r = "%s (%s)" % (r, url)

      return r
    desc = get_desc(url)

    pub = open(keyfile_base+".pub", "r").read().strip()
    if not pub:
      raise SimpleError("Public key is missing!")

    def output ():
      print("\nDeploy key for %s:" % (desc,))
      print(pub)
      print()

    if created:
      llog.info("Created deploy key for remote '%s'", remote)

    return output

  @staticmethod
  def _get_archive_log_kvs (raw_log):
    """
    Parse a depz-generated log message

    When depz initializes a repo based on an archive, it creates a commit of
    a specific form.  This form has a specific author email address, a
    specific "subject" line of the commit message, and then possibly a number
    of key-value pairs (this can be read by using the %ae%n%B git log format).
    This method checks that the log message is valid, returns None of it is
    not, and returns a dictionary of key-value pairs if it is.
    """
    log_message = strsplit(raw_log, "\n", 2)
    if len(log_message) != 3: return None
    _,email,subject = log_message
    if "\n" in subject:
      subject,message = subject.split("\n",1)
    else:
      message = ''

    subject = subject.strip()

    if email != "depz@depz.invalid": return None
    if subject != "Initial commit from archive by depz": return None

    message = strsplit(message.strip())
    kvs = {}
    for kv in message:
      kv = kv.lstrip()
      if kv.startswith("#"): continue
      kv = kv.split("=",1)
      if len(kv) == 1:
        kvs[kv[0]] = True
      else:
        kvs[kv[0]] = kv[1]

    return kvs

  @classmethod
  def _sanity_check_archive_repo (cls, git, rr):
    """
    Check if an archive-derived repo is sane

    Returns True if the repo does seem to be based on the config.
    Returns an error string otherwise.
    """
    first_log = git.run_capture("rev-list --max-parents=0 HEAD "
                                "--format=format:%ae%n%B",
                                check=False)
    kvs = cls._get_archive_log_kvs(first_log)
    if kvs is None or "init_archive" not in kvs:
      return ("Repository's current branch does not start with a depz "
              "archive log entry")

    for k,v in kvs.items():
      if rr.get(k,None) != v:
        return ("Repository seems mismatched with configured archive; "
                "key '%s' does not match" % (k,))

    # All keys match
    return True

  def do_sanity_check (self, rname, rr):
    """
    Sanity checks the repo

    This may actually check properties of the git repos themselves, because it
    should be run after do_init

    This is a lot like do_init, but it complains instead of taking action.
    """
    llog = log.getChild(rname)
    proxy = rr.val

    git = Git(proxy.full_directory)
    git.check_toplevel()

    if not os.path.isdir(os.path.join(git.path, ".git")):
      raise SimpleError("Does not seem to be a git repository")

    if not git.is_valid:
      raise SimpleError("Does not seem to be a valid git repository")

    remotes = self._get_conf_remotes(rr)
    urls = {x:k for k,x in remotes.items()}

    # Remotes in repo
    rremotes = git.remotes
    rurls = {x:k for k,x in rremotes.items()} # url->remote-name

    if not remotes and rr.get("init_archive",False):
      # We can't check that this archive is set up correctly by comparing
      # remotes because the config file doesn't specify any remotes!  So it's
      # probably an archive-only repo.  We can sanity check that the current
      # branch corresponds to the specified archive, though, so let's do that.

      tmp = self._sanity_check_archive_repo(git, rr)
      if tmp is True:
        if not args.init:
          llog.debug("Repository seems to be derived from archive")
      else:
        llog.warn("Repository does not seem to be derived from archive: %s",
                  tmp)

    else: # Not a remoteless archive
      if not rremotes:
        raise SimpleError("Repo has no remotes configured")

      if set(urls.keys()).intersection(rurls.keys()):
        pass
      else:
        raise SimpleError("Repo unusable because it exists but doesn't "
                          "seem related to the depz information")

      if set(remotes.keys()).difference(rremotes.keys()):
        missing = sorted(set(remotes.keys()).difference(rremotes.keys()))
        llog.warn("Repo is missing remote: %s", " ".join(missing))

  def do_early_sanity_check (self, r, rr):
    """
    Sanity checks repo entries

    This is basically checking the keys of the entry to make sure they're sane
    (and that ones we expect to be there are there).
    """
    if rr.get("skip",False):
      log.debug("Skipping repo %s due to configuration", r)
      self.add_error_repo(r)
      return

    for attr in "full_directory name type remote_name checkout checkout_remote group".split():
      if attr not in rr:
        log.error("Skipping repo %s because it has no '%s'", r, attr)
        self.add_error_repo(r)
        return
      if not rr.get(attr):
        log.error("Skipping repo %s because '%s' is empty", r, attr)
        self.add_error_repo(r)
        return

    if not os.path.isabs(rr.val.full_directory):
      log.error("Skipping %s because it does not have an absolute path",r)
      self.add_error_repo(r)
      return
    for k in rr.keys():
      k = k.split(None,1)
      if len(k) > 1 and k[0] == "remote": break
    else:
      if "init_archive" in  rr:
        #log.warn("Repo %s has no remotes, which is not recommended, but is "
        #         "being allowed since it has an init_archive", r)
        log.info("Repo %s is archive-only (it has no remotes)", r)
      else:
        log.error("Skipping repo %s because it has no remotes", r)
        self.add_error_repo(r)

  def do_update (self, rname, rr):
    llog = log.getChild(rname)
    if rr.get_bool("update_skip", False):
      llog.debug("Skipping update due to configuration")
      return

    git = Git(rr.val.full_directory)
    rremotes = git.remotes
    if not rremotes:
      llog.debug("Repository has no remotes")
      return
    success = False
    errs = []
    err_remotes = []
    for rem,url in rremotes.items():
      sshcmd = self._get_ssh_cmd(git,rname,rr,rem)
      add_env = {'GIT_SSH_COMMAND':sshcmd} if sshcmd else None
      use_dk = " using deploy key" if sshcmd else ""

      llog.info("Updating remote '%s' (%s)%s", rem, url, use_dk)
      #r = git.run_show(["remote","update",rem], check=False)
      r = git.run(["remote","update",rem], stdouterr_together=True, check=False, add_env=add_env)
      if r.returncode == 0:
        success = True
      else:
        errs.append(r.stdout.strip())
        err_remotes.append(rem)
        llog.warn("Updating remote %s failed with code %s" % (rem,r.returncode))
    if not success:
      git_out = "\n".join(errs)
      if git_out:
        git_out = "\n" + git_out
      else:
        git_out = " <None>"
      llog.error("All remotes failed to update.  git output:" + git_out)
      raise SimpleError("All remotes failed to update")
    #elif errs:
    #  llog.info("Some remotes failed to update: %s", " ".join(err_remotes))

  def do_show_outdated (self, rname, rr):
    if not App.is_current_branch_valid(rname,rr): return
    llog = log.getChild(rname)
    git = Git(rr.val.full_directory)

    current_branch = git.current_branch
    checkout_branch = rr.val.checkout

    # Remove remotes with duplicate URLs by flipping twice
    remotes = git.remotes
    remotes = {v:k for k,v in remotes.items()}
    remotes = {v:k for k,v in remotes.items()}
    remotes = remotes.keys()

    def check (branch, compares):
      success = False
      all_current = True
      for c in compares:
        cmd = ["rev-list","--left-right","--count","%s...%s"%(branch,c)]
        try:
          o = git.run_capture(cmd, check=True)
        except Exception:
          continue
        success = True
        o = o.strip().split()
        if len(o) != 2: raise SimpleError("Can't compare branches")
        ahead=int(o[0])
        behind=int(o[1])
        if ahead==0 and behind==0: continue
        if behind>0: all_current=False
        if ahead>0 and behind>0:
          llog.warn("Current branch %s is %s behind %s (and %s ahead)", branch, App.pluralize(behind,"commit"), c, ahead)
          llog.info("(It appears the repository is in a conflicted state with its origin.)")
          llog.info("(If the repo has local changes, you may want to manually merge or otherwise resynchronize it.)")
          llog.info("(If the repo doesn't have local changes you can delete it and run 'depz --init' to restore it.)")
        elif behind>0:
          llog.warn("Current branch %s is %s behind %s", branch, App.pluralize(behind,"commit"), c)
          llog.info("(You may want to use 'depz --ff' to fast-forward and apply those changes.)")
        elif ahead>0:
          llog.warn("Current branch %s is %s ahead of %s", branch, App.pluralize(ahead,"commit"), c)
          llog.info("(You will need to manually push those commits if desired.)")
      return success

    compares = [r+"/"+current_branch for r in remotes]
    if current_branch != checkout_branch:
      compares = [r+"/"+checkout_branch for r in remotes]
    tracked = git.get_tracked_by(current_branch)
    if tracked not in compares: compares.append(tracked)
    if current_branch != checkout_branch:
      tracked = git.get_tracked_by(checkout_branch)
      if tracked not in compares: compares.append(tracked)

    if "monitor_branch" in rr:
      monitors = strsplit(rr.val.monitor_branch.replace(","," "))
      for m in monitors:
        if m not in compares: compares.append(m)

    ok = check(current_branch, compares)
    if current_branch != checkout_branch:
      if check(checkout_branch, compares): ok = True

    if not ok:
      checkout = rr.val.checkout
      remote_prefs = ["refs/remote_tags/%s/%s" % (r,checkout) for r in
                      rr.val.checkout_remote.replace(","," ").split()]
      current_hash = git.current_hash
      for r in remote_prefs:
        try:
          if git.get_ref_hash(r) == current_hash:
            log.debug("Current head is tag %s and tags can't be outdated", r)
            break
        except Exception:
          pass
      else:
        llog.warn("Couldn't tell if anything was outdated.  Are there working remotes?")

  def do_fast_forward (self, rname, rr):
    llog = log.getChild(rname)
    proxy = rr.val
    if rr.get_bool("fast_forward_skip", False):
      llog.debug("Skipping fast forward due to configuration")
      return

    if not App.is_current_branch_valid(rname,rr): return

    git = Git(rr.val.full_directory)

    branches = []

    current = git.current_branch
    tracking = git.tracking_branch
    if not tracking:
      llog.warn("Current branch '%s' has no tracking branch", current)
    else:
      branches.append(tracking)

    if "monitor_branch" in rr:
      monitors = strsplit(rr.val.monitor_branch.replace(","," "))
      for m in monitors:
        if m not in branches: branches.append(m)

    def try_it (branch):
      r = git.run_hide(["merge-base","--is-ancestor",current,branch], check=False)
      if r == 0:
        llog.info("Fast forwarding %s to %s", current, branch)
        r = git.run_show(["merge","--ff-only",branch], check=False)
        if r != 0:
          llog.error("Fast forward merge failed")
      else:
        llog.warn("Could not fast-forward. Check the branch status with 'depz --outdated'.")

    for b in branches:
      try_it(b)

  def do_init (self, rname, rr):
    llog = log.getChild(rname)
    proxy = rr.val

    git = Git(proxy.full_directory)
    llog.debug("Initializing repo %s", rname)

    def check_emptyish (files):
      files = set(files)
      for f in "depz_deploy_key.private depz_deploy_key.pub".split():
        files.discard(f)
      if files: return False
      return True

    if not os.path.exists(git.path):
      llog.debug("Making directory %s", git.path)
      os.makedirs(git.path, exist_ok=True)
    elif not os.path.isdir(git.path):
      raise SimpleError("Path for repo exists but isn't a directory")
    elif check_emptyish(os.listdir(git.path)):
      # It's empty(ish); that's fine
      pass
    elif not os.path.isdir(os.path.join(git.path, ".git")):
      raise SimpleError("Repo directory exists, isn't empty, but doesn't "
                        "seem to be a git repo")
    else:
      # It looks like a git repo.  Is it the right one?
      # Desired remotes
      remotes = self._get_conf_remotes(rr)
      urls = {x:k for k,x in remotes.items()}

      # Remotes in repo
      rremotes = git.remotes
      rurls = {x:k for k,x in rremotes.items()} # url->remote-name

      if not remotes and rr.get("init_archive",False):
        tmp = self._sanity_check_archive_repo(git, rr)
        if tmp is True:
          llog.debug("Repository seems to be derived from archive")
        else:
          raise SimpleError("Repository does not seem to be derived from "
                            "archive: %s" % (tmp,))
      elif not rremotes:
        if git.is_empty_branch and git.is_clean:
          # No remotes and no commits
          llog.debug("Appears to be an empty git repo; will initialize it")
          create = True
        else:
          raise SimpleError("Repo is unusable because it has commits and/or "
                            "staged changes but no remotes")
      elif set(urls.keys()).intersection(rurls.keys()):
        # At least one common remote -- we can use it
        pass
      else:
        raise SimpleError("Repo unusable because it exists but doesn't "
                          "seem related to the depz information")

    if git.run_hide("init", check=False) != 0:
      raise SimpleError("git init failed")

    remotes = self._get_conf_remotes(rr)
    rremotes = git.remotes
    generated_keys = {} # remote->display_key_info
    def show_new_keys ():
      for f in generated_keys.values():
        f()
    self.add_command(show_new_keys, priority=FINISH_PRIORITY)
    for remote in set(remotes.keys()).difference(rremotes.keys()):
      llog.info("Adding missing remote '%s' -> %s", remote, remotes[remote])

      dk = self._get_conf_remote_uses_deploy_key(rr, remote)
      if dk:
        if not git.has_deploy_key(remote):
          if dk is not True:
            # dk files!  Use them!
            def copyit (src, dst):
              if os.path.exists(dst):
                raise SimpleError("Key file already exists")
              with open(src, "r") as infile:
                data = infile.read()
              with os.fdopen(os.open(dst, os.O_WRONLY|os.O_CREAT, mode=0o600), "w") as o:
                o.write(data)

            copyit(dk+".pub", git.get_keyfile_base(remote)+".pub")
            copyit(dk+".private", git.get_keyfile_base(remote)+".private")
            llog.debug("Copied existing keys for remote '%s'", remote)
          else:
            # Generate new ones
            display_info = self._gen_deploy_key(git, rname, rr, remote)
            if display_info: generated_keys[remote] = display_info
      git.run_show(["remote","add",remote,remotes[remote]], check=True)

    for remote in set(remotes.keys()).difference(rremotes.keys()):
      if remote in generated_keys:
        if sys.stdout.isatty():
          llog.info("Need to set up deploy key for remote %s", remote)
          generated_keys.pop(remote)()
          input("Press enter after setting the deploy key on the server\n"
                "(or replacing the one in the repository). ")
      sshcmd = self._get_ssh_cmd(git,rname,rr,remote)
      add_env = {'GIT_SSH_COMMAND':sshcmd} if sshcmd else None

      cmd = ["fetch",remote,"--no-tags"]
      r = git.run_auto(cmd, check=False, add_env=add_env, log_level=logging.INFO)
      if r == 0:
        llog.info("Fetched new remote '%s'", remote)
        if not rr.get_bool("no_tags"):
          # Fetch again, this time with normal tag behavior
          r = git.run_hide(["fetch",remote], check=False, add_env=add_env)
          if r == 0:
            llog.debug("Fetched tags for '%s'", remote)
          else:
            llog.warn("Failed while fetching tags for '%s'", remote)
        # Fetch again, this time for tags into special remote_tags namespace
        r = git.run_hide(["fetch",remote,"--no-tags","+refs/tags/*:refs/remote_tags/"+remote+"/*"], check=False, add_env=add_env)
        if r == 0:
          llog.debug("Fetched all remote tags for '%s'", remote)
        else:
          llog.warn("Failed to fetch new remote tags for '%s'", remote)
      else:
        llog.error("Failed to fetch new remote '%s'", remote)

    if git.is_empty_branch:
      checkout = proxy.checkout
      remote_prefs = [(r+"/"+checkout,False) for r in
                      proxy.checkout_remote.replace(","," ").split()]
      remote_prefs += [("refs/remote_tags/%s/%s" % (r,checkout),True) for r in
                      proxy.checkout_remote.replace(","," ").split()]

      if checkout in git.local_branches:
        tracked = git.get_tracked_by(checkout)
        def check_if_tag (cur_hash):
          for (r,is_tag) in remote_prefs:
            if not is_tag: continue
            if git.get_ref_hash(r) == cur_hash: return True
          return False
        if ((tracked,False) not in remote_prefs) and not check_if_tag(git.get_ref_hash(checkout)):
          llog.warn("Checkout branch '%s' exists but does not track an "
                    "expected remote and does not seem to reference a remote tag")
        else:
          git.run_checkout(["checkout",checkout], check=True)
      else:
        def check_branch ():
          for rem,is_tag in remote_prefs:
            r = git.run(["branch",checkout,rem], stdouterr_together=True, check=False)
            if r.returncode == 0:
              git.run_checkout(["checkout", checkout], check=True)
              llog.info("Checked out %s '%s'", "tag" if is_tag else "branch", checkout)
              break
            llog.debug("Couldn't create local branch for checkout '%s'", rem)
          else:
            return False
          return True

        def check_hash ():
          #TODO: I guess this is just a simple check that the hash exists?
          #      There's probably a faster/better way.
          r = git.run_hide(["checkout",checkout], check=False)
          if r != 0: return False
          h = git.current_hash
          ch = "checkout_" + h
          if ch in git.local_branches:
            git.run_checkout(["checkout",ch], check=True)
            if git.current_hash != h:
              raise SimpleError("Head of branch %s doesn't have hash %s!",
                                ch, h)
            llog.info("Checked out existing checkout branch '%s'", ch)
          else:
            git.run_hide(["checkout","-b",ch], check=True)
            llog.info("Checked out new checkout branch '%s'", ch)
          return True

        if is_hex(checkout) and len(checkout) == 40:
          # Looks like a sha1; only try matching as hash
          success = check_hash()
        elif is_hex(checkout):
          success = check_branch()
          if not success:
            success = check_hash()
        else:
          success = check_branch()

        if not success:
          init_archive = rr.get("init_archive",None)
          if init_archive:
            llog.debug("Attempting to initialize from archive '%s'",
                       init_archive)
            sha1 = rr.get("init_archive_sha1",None)
            sha256 = rr.get("init_archive_sha256",None)
            sha512 = rr.get("init_archive_sha512",None)
            try:
              ga = get_archive(init_archive, git.path,
                               sha1=sha1,sha256=sha256,sha512=sha512)
              # Originally, I was going to do much more "rounding" here to try
              # to ensure that even systems with pretty broken filesystem
              # times arrived at the same answer.  But with modern systems,
              # hopefully this just isn't a problem.  So let's just round to
              # the minute and see what happens.
              # (If there was a good way to extract the time from the archive
              # itself, that'd be even better, but it looked like it'd be
              # harder than seemed worthwhile at the moment.)
              t = int(ga[2])
              if t < ga[2]: t += 1    # Round seconds up
              t = (59 + t) // 60 * 60 # Round minutes up
              t = "%s +0000" % (t,)
              add_env = {"GIT_COMMITTER_DATE": t}

              git.run_hide(["checkout","-b",checkout], check=True)
              git.run_hide("add .", check=True)
              message = "Initial commit from archive by depz\n"
              message += "\nname=" + rname
              message += "\ninit_archive=" + init_archive
              if sha1:   message += "\ninit_archive_sha1="   + sha1
              if sha256: message += "\ninit_archive_sha256=" + sha256
              if sha512: message += "\ninit_archive_sha512=" + sha512

              git.run_hide(["-c","user.name=depz",
                            "-c","user.email=depz@depz.invalid",
                            "commit","-m",message,
                            "--author=depz <depz@depz.invalid>",
                            "--date",t],
                           check=True, add_env=add_env)
            except Exception:
              llog.error("Exception while trying to initialze from archive "
                         "'%s'", init_archive)
              raise
            llog.info("Initialized from archive '%s'", init_archive)
          else:
            raise SimpleError("Could not check out '%s'" % (checkout,))
    elif git.is_detached:
      llog.info("Repository is curently detached (checkout is '%s')",
                proxy.checkout)
    elif git.current_branch != proxy.checkout:
      pc = proxy.checkout.lower()
      log_wrong = False
      if is_hex(pc):
        if git.current_hash == pc:
          pass # All good
        elif git.current_hash.startswith(pc):
          llog.debug("Currently on branch '%s' which looks like it "
                     "corresponds to checkout hash '%s'", git.current_branch,
                     pc)
        else:
          log_wrong = True
      else:
        log_wrong = True

      if log_wrong:
        llog.info("Currently on branch '%s' (checkout is '%s')",
                  git.current_branch, proxy.checkout)

  @classmethod
  def is_current_branch_valid(cls,rname,rr):
    git = Git(rr.val.full_directory)
    if git.current_branch: return True

    llog = log.getChild(rname)
    llog.warn("No current branch or in a detached HEAD state.")
    if "checkout" in rr._dict:
      llog.info("(You may want to manually 'git checkout " + rr.val.checkout + "' in the repo.)")
    else:
      llog.info("(You may want to manually 'git checkout master' or other default branch in the repo.)")
    return False

  @classmethod
  def pluralize (cls,count,word):
    if count==1: return "1 " + word
    else:        return str(count) + " " + word + "s"


import subprocess
_DEVNULL = open(os.devnull, "w")

class GitConfigProxy (object):
  def __init__ (self, git):
    self._git = git

  def __setitem__ (self, key, value):
    self._git.run_hide(["config",key,value], check=True)

  def __getitem__ (self, key):
    r = self.get(key)
    if r is None: raise KeyError(key)

  def get (self, key, default=None):
    try:
      return self._git.run_capture(["config",key], check=True)
    except Exception:
      return default


class Git (object):
  def __init__ (self, path):
    assert os.path.isabs(path)
    self.path = os.path.abspath(path)

  @property
  def conf (self):
    return GitConfigProxy(self)

  def get_keyfile_base (self, remote):
    keyfile_base = os.path.join(self.path, "depz_deploy_key")
    keyfile_base += "." + remote.replace(" ","-")
    return keyfile_base

  def has_deploy_key (self, remote):
    keyfile_base = self.get_keyfile_base(remote)
    return (os.path.exists(keyfile_base+".private")
            and os.path.exists(keyfile_base+".pub"))

  @property
  def toplevel_directory (self):
    return self.run_capture("rev-parse --show-toplevel", check=True)

  def check_toplevel (self):
    try:
      if self.path != self.toplevel_directory:
        raise SimpleError("Bad repository path")
    except Exception:
      raise SimpleError("Bad repository path")

  @property
  def all_refs (self):
    return strsplit(self.run_capture("show-ref", check=False), "\n")

  def get_remotes (self, kind = "fetch"):
    remotes = self.run_capture("remote -v").strip().split("\n")
    ret = {}
    for remote in remotes:
      if not remote: continue
      assert remote.endswith(" (fetch)") or remote.endswith(" (push)"), remote
      remote,remote_kind = remote.rsplit(" ",1)
      remote_kind = remote_kind[1:-1]
      if remote_kind != kind: continue
      name,url = remote.split(None,1)
      ret[name] = url
    return ret

  # The code below has problems when there are no commits yet...
  #@property
  #def has_uncomitted (self):
  #  r = self.run("diff-index --quiet HEAD --", stdouterr_together=True,
  #               check=False)
  #  if r.stdout.strip() == "fatal: bad revision 'HEAD'": return 3 #False
  #  return r.returncode != 0

  @property
  def is_clean (self):
    """
    Clean if there are no modified or new files, etc. (status is empty)
    """
    r = self.run_capture("status --porcelain", check=True)
    r = strsplit(r, "\n")
    r = [x for x in r if not x.startswith("#")]
    return False if r else True

  @property
  def remotes (self):
    return self.get_remotes()

  @property
  def local_branches (self):
    r = self.run_capture("branch").strip().split("\n")
    o = []
    for b in r:
      if not b: continue
      f = b[0]
      b = b[2:]
      if f == "*": o.insert(0, b)
      else: o.append(b)
    return o

  def get_tracked_by (self, branch):
    """
    Return the branch tracked by "branch" or None
    """
    r = self.run_capture(["rev-parse","--abbrev-ref",branch+"@{upstream}"], check=False)
    if not r: return None
    return r

  @property
  def is_valid (self):
    r = self.run_capture("status --porcelain -b", check=False).split("\n",1)[0]
    return r.startswith("## ")

  @property
  def is_empty_branch (self):
    r = self.run_capture("status --porcelain -b", check=False).split("\n",1)[0]
    if not r.startswith("## "): raise RuntimeError("Bad repository?")
    if r.startswith("## Initial commit on "): return True # git 2.7.4
    if r.startswith("## No commits yet on "): return True # git 2.20.1
    return False

  @property
  def current_branch (self):
    r = self.run_capture("status --porcelain -b", check=False).split("\n",1)[0]
    if not r.startswith("## "): raise RuntimeError("Bad repository?")
    if r.startswith("## Initial commit on "):
      return r.split(None,4)[4]
    if r == "## HEAD (no branch)":
      return None # Detached head (Should this be ""?)
    r = r.split("...",1)[0]
    return r[3:]

  @property
  def current_hash (self):
    return self.get_ref_hash("HEAD")

  def get_ref_hash (self, ref):
    return self.run_capture(["rev-parse","--verify",ref], check=True)

  @property
  def is_detached (self):
    return self.current_branch is None

  @property
  def tracking_branch (self):
    r = self.run_capture("status --porcelain -b", check=False).split("\n",1)[0]
    if not r.startswith("## "): raise RuntimeError("Bad repository?")
    if r.startswith("## Initial commit on "): return None
    if "..." not in r: return None
    r,track = r.split("...")
    track = track.rsplit(" [",1)[0]
    return track

  @staticmethod
  def _make_env (env, add_env):
    if env is None and add_env is None: return None
    if env is None:
      env = os.environ
    if add_env:
      env = env.copy()
      env.update(add_env)
    return env

  def run_auto (self, *args, **kw):
    """
    Either does run_show or run_hide depending on the log level

    log_level should be the level at which you want it to show (defaults to INFO)
    """
    log_at = kw.pop("log_level", logging.INFO)
    f = self.run_show
    if cur_log_level > log_at:
      f = self.run_hide
    return f(*args, **kw)

  def run_checkout (self, cmd, *args, **kw):
    """
    Meant for running git checkout

    If quiet=True (the default), it prints progress if on a terminal, but is
    otherwise quiet (as in git checkout -q).
    """
    if isinstance(cmd, str): cmd = cmd.split()
    if cmd[0] != "checkout": raise RuntimeError("Bad checkout command")
    quiet = kw.pop("quiet", True)
    if quiet:
      if log_is_tty: cmd.insert(1, "--progress")
      # Would rather not check log_is_tty here, but in general, we don't know
      # so I don't know what the clean alternative is.
      cmd.insert(1, "-q")
    return self.run_auto(cmd, *args, **kw)

  def run_hide (self, cmd, check=True, env=None, add_env=None):
    env = self._make_env(env, add_env)
    if isinstance(cmd, str): cmd = cmd.split()
    cmd.insert(0, "git")
    r = subprocess.run(cmd, stdout=_DEVNULL, stderr=_DEVNULL, cwd=self.path,
                       check=check, env=env)
    return r.returncode

  def run_show (self, cmd, check=True, env=None, add_env=None):
    env = self._make_env(env, add_env)
    if isinstance(cmd, str): cmd = cmd.split()
    cmd.insert(0, "git")
    r = subprocess.run(cmd, cwd=self.path, check=check, env=env)
    return r.returncode

  def run (self, cmd, stdouterr_together=False, check=True, env=None, add_env=None):
    env = self._make_env(env, add_env)
    if isinstance(cmd, str): cmd = cmd.split()
    cmd.insert(0, "git")
    sout = subprocess.PIPE
    serr = subprocess.PIPE
    if stdouterr_together: serr = subprocess.STDOUT
    r = subprocess.run(cmd, universal_newlines=True, stdout=sout, stderr=serr, cwd=self.path, check=check, env=env)
    return r

  def run_capture (self, cmd, check=True, env=None, add_env=None):
    env = self._make_env(env, add_env)
    if isinstance(cmd, str): cmd = cmd.split()
    cmd.insert(0, "git")

    r = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.path, check=check, env=env)
    if r.returncode != 0: return ""
    return r.stdout.strip()


if __name__ == '__main__':
  main()
