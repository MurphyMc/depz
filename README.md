# depz

First and foremost: Please note that depz is an experimental tool!

depz is a tool for managing groups of source code repositories.  The intended
use cases are similar to those addressed by git subtree and submodules --
you've got a project that incorporates code from other projects (libraries
and so on).  depz is different in that it tries to facilitate some flexible
workflows, where different users may be working with their own forks of
the sub-repositories, you may be simultaneously working with your own (or an
organizational) fork as well as trying pulling in changes from upstream,
etc.

A project will generally have one or more .depz files which describe the
sub-repositories and sketch out how they should be worked with.  This file
will be stored in the project's main repository.  After cloning that repo,
the user can run depz to fetch the sub-repositories, and can subsequently
run depz to check if they have become outdated, merge changes (in simple
cases), and so on.  It is not meant to completely automate arbitrarily
complex workflows.  For example, if you have local changes on some feature
branch and the upstream project updates, you should expect to have to get
in there and use git as usual.  However, if you just get in the habit of
running depz occasionlly, you'll at least *notice* when sub-repositories
go out of date without being *forced* to update them on someone else's
timescale.

A common pattern will be for the main project .depz file to also "include"
a local configuration file which is not under source control.  This allows
an individual developer to override project settings with their own (e.g.,
to stop add their own remote, stop a repository from updating because
they are actively developing it, etc.).

Ideally, depz would work with many different source control systems.  For
now, it works with git.  However, it also seems to work okay with Mercurial
via git-remote-hg.

## Installation

depz requires Python 3.5 and git 2.7, neither of which are particularly
new anymore.  If you want to use Mercurial repositories, you will also want
git-remote-hg.  On Ubuntu, you can install this with:
```
sudo apt install git-remote-hg
```

If you'd like colored logs, you'll need to tweak your configuration (see the
next section), but first you'll also want to do:
```
sudo apt install python-coloredlogs
```

You can install depz using the included setup.py.  To install it from git
for just your user account, you can do:
```
pip3 install --user git+https://github.com/MurphyMc/depz.git
```

You can also clone and install it separately like so:
```
git clone https://github.com/MurphyMc/depz
pip3 install --user ./depz
```

If all goes well, after doing the above, you'll have the depz command
available to you.  You can check with `depz --help`.

## Customizing Your Installation

When depz starts up, it tries to read a file called .depzconfig from your
home directory.  You can create this file with a text editor.  At present,
the most useful thing you can probably do with it is to customize the
logging.  Here's a sample .depzconfig:
```
[depz]
log_level=debug
color_log=true
```

The log levels are pretty self-explanatory and are the same as used by
the `--log-level` commandline parameter (see `depz --help`).
