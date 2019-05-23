# depz

*First and foremost: Please note that depz is an experimental tool!  It
was hacked together pretty quickly and it shows, but with some luck it
will evolve into something nice.  For now: caveat emptor.*

depz is a tool for managing groups of source code repositories.  The intended
use cases are similar to those addressed by git subtree and submodules --
you've got a project that incorporates code from other projects (libraries
and so on).  depz is different in that it tries to facilitate some flexible
workflows, where different users may be working with their own forks of
the sub-repositories, you may be simultaneously working with your own (or an
organizational) fork as well as trying pulling in changes from upstream,
etc.

Here's a quick feature list:

* Flexible config files let you define and group repositories
* You can have "local" config files which override settings (e.g., to add
  an additional remote for your own fork)
* Can clone git, Mercurial, and Bazaar repositories
* Can initialize a repository from a zip/tgz archive somewhere, including
  creating a stable first commit for it so that if you and others all do it
  and then make commits, you have shared history
* Can automatically generate and assist you with repository-specific (and
  optionally read-only) GitHub deploy keys, which are a nice option when you
  are working with private repositories on an untrusted machine where you
  don't want to put your credentials
* Can check to see which local repositories are ahead/behind remote
  repositories
* Fast-forward merge subrepositories with a single command
* Can monitor other *local* branches (so that you can fast-forward merge
  branches which were *pushed* from elsewhere)

## The Basics

A project will generally have one or more .depz files which describe the
sub-repositories and sketch out how they should be worked with.  This file
will be stored in the project's main repository.  After cloning that repo,
the user can run depz to fetch the sub-repositories, and can subsequently
run depz to check if they have become outdated, merge changes (in simple
cases), and so on.  It is not meant to completely automate arbitrarily
complex workflows.  For example, if you have local changes on some feature
branch and the upstream project updates, you should expect to have to get
in there and use git as usual.  However, if you just get in the habit of
running depz occasionally, you'll at least *notice* when sub-repositories
go out of date without being *forced* to update them on someone else's
timescale.

A common pattern will be for the main project .depz file to also "include"
a local configuration file which is not under source control.  This allows
an individual developer to override project settings with their own (e.g.,
to stop add their own remote, stop a repository from updating because
they are actively developing it, etc.).

Ideally, depz would work with many different source control systems.  For
now, it works with git.  However, it can also be made to work with Mercurial
and Bazaar repositories (see later sections in this document).

## Installation

depz requires Python 3.5 and git 2.7, neither of which are particularly
new anymore.  If you want to use Mercurial repositories, you will also want
git-remote-hg.  If you want to work with Bazaar repositories, you will want
git-remote-bzr.  On Ubuntu, you can install these with:
```
sudo apt install git-remote-hg git-remote-bzr
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

Notably, if you have a project that utilizes depz to manage its dependencies,
you should now be able to `cd` into its directory, execute `depz --init`, and
be on your way!

# Invoking depz

depz is invoked from the commandline.  If you've installed it with pip, it is
hopefully in your path and just called `depz`.  If you just grabbed the `.py`
file, then you may have to invoke it as `depz.py`.

When executed, depz does basically three things:

* Load one or more `.depz` configuration files that hopefully contain
  information about repositories.
* Filter the list of repositories.
* Possibly execute one or more commands, which generally apply some operation
  to each repository.

The exact details of these three phases can be controlled with various
commandline options.  The following subsection examines the first two, and the
subsection after that examines the various commands.  You can get more brief
help by using the `--help` commandline option.

## Selecting Which Repositories

By default, depz will load all `.depz` configuration files in the current
directory, and will filter out any repository not in the "default" group.
You can adjust both of these behaviors.

Firstly, you can use the `--depz` option to specify a particular `.depz`
file to load.  You can also point it at a directory to load all the `.depz`
files in that directory.  This option can be given more than once to select
multiple files or directories.

Secondly, you can switch which groups of repositories to act on by using the
`--group` option (see the section on configuring repositories for more info
on groups in general).  In the simplest case, you can simply do something like
`--group=libraries` to select all repositories in the "libraries" group.
However, you can also specify multiple groups, and any repository in any of
those will be included.  For example: `--group=libraries,examples`.  The list
of groups can contain glob-like wildcards, so if you were in the unfortunate
situation of having a group called "libs" and a group called "libraries", you
could do `--group=lib*`.  Lastly, you can _subtract_ groups.  So you could
do something like `--group=*,-libraries` to select everything _except_
libraries.

You can also specify specific repositories by name using the `--name` option.
While it was claimed above that the default group filter is "default", this
changes when `--name` is specified so that the default group filter is "\*"
instead (otherwise, you might specify a repository by name, but if it wasn't
in the "default" group, it wouldn't be matched).  If you want to specify a
name and only want it to match the default group, you'll have to explicitly
state `--group=default`.

As with groups, you can actually specify a list of names, and you can use
wildcards, so you could do something like `--name=ro*` to match both
"rogue" and "rogo".

## Commands on Repositories

The whole point of depz is to execute various operations for various
repositories mentioned in its configuration files.  In the following
subsections, we look at some of these commands.

### --dump

The `--dump` command is mostly meant for debugging.  It lists the repositories
and their settings in a format similar to that used in the config files.  It
can optionally be given an argument, which may be `early` (the default),
`late`, or `all`.  In the last case, it lists every repo it can find in the
config files.  `early` shows repos after filtering (e.g., via the `--name` and
`--group` options) -- the ones that should actually be acted upon by the
current invocation.  `--late` waits until they have been sanity checked before
listing them; for example, this means ones with no directory will not be
listed.

### --init

This command is used to actually create the local repositories described by
the config files.  That is, it will create the local directories, attempt to
fetch the initial code, and set local repo to point at the desired initial
branch (the "checkout" in depz terminology).

It is also at least _supposed_ to be safe to run the `--init` command at any
later time and can act as a bit of a sanity check of existing repositories
in that case.

### --update

This option fetches updated code from remotes (e.g., a "git fetch" for git
repositories).

### --outdated

This option attempts to help you find repositories where the local code is now
out of date.  For example, code where the remote tracking branch or a
monitored local branch (see the information on the `monitor_branch` repo
option in the Configuring Repositories section for more) is ahead of the local
branch.

### --fast-forward (--ff)

This option attempts to rectify things when your branch has become outdated by
fast-forwarding it.  Obviously this won't always be a suitable or workable
option, but it should be for the easy cases.

# Customizing Your Installation

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

To learn more about depz configuration files, see the following sections.

# depz Configuration Files in General

Perhaps the key component of depz are its configuration files.  If you are
simply using depz to grab dependencies for a project, it's possible that you
never really have to see or care about them.  On the other hand, if you want
to customize how you work with repositories or if you are the author (or
maintainer) of a project that is going to manage sub-repositories with
depz, understanding how the configuration files work may be crucial.  The
following subsections describe their workings in some detail.  If you're a
get-your-hands-dirty-first type, you might also skip ahead to the section
on Configuring Repositories and refer back to this one to understand what
is going on.

depz configuration files all use the same format and are all technically
equivalent.  For organizational reasons, one might break them down into
files using the `.depzconfig` extension for general configuration and files
using the `.depz` extension for files which actually describe
sub-repositories.  By default, depz looks for any such files in the current
working directory, though this can be altered by giving the paths to one or
more configuration file or directory containing `.depz` or `.depzconfig`
files via the `--repo` commandline option.

The files are text files in a fairly typical "INI"-type format that consists
of sections that begin with a section header enclosed by brackets, and
key=value pairs within those sections.  You saw a simple example of such a
file in the "Customizing Your Installation" subsection above.

Going a bit beyond typical INI files, there are a number of special features.
We look at these in the rest of this section.

## Including More Configuration Files

One config file can include other config files.  This is done by using what
looks like a section header, except it is composed of two parts: the first is
the word "INCLUDE" and the second is a path to another configuration file.
An alternate form is the same except it uses the word "TRY-INCLUDE".  The
difference is that if the specified file is unavailable, it causes an error
with the first form, and is happily ignored with the second form.  As an
example, consider the following config file which requires that the file
`mysubproject/subprojectsubprojects.depz` is available, and also tries to
include optional user settings from `local.depzconfig`:
```
[INCLUDE mysubproject/subprojectsubprojects.depz]
[TRY-INCLUDE local.depzconfig]
```

It is safe for inclusions to create cycles -- after the first time a file is
included, it will be ignored for subsequent inclusions.

## Section Ordering, Overriding, and Defaults

When you have multiple files (either due to explicit inclusion using the
commandline or via `INCLUDE` and `TRY-INCLUDE` directives), a section may
appear more than once (i.e., in more than one file).  When keys do not
overlap, this can simply be thought of as merging all the sections with
the same name into one big section.  When the same key appears in sections
with the same name in different files, things get a little more complex.
Consider the following four configuration files.

A.depz:
```
[INCLUDE B.depz]
[INCLUDE C.depz]

[mysection]
myvalue=A's value
```

B.depz:
```
[INCLUDE D.depz]

[mysection]
myvalue=B's value
```

C.depz:
```
[mysection]
myvalue=C's value
```

D.depz:
```
[mysection]
myvalue=D's value
```

Assuming you load `A.depz`, what is the effective value of
`[mysection].myvalue`?  It's "A's value".  One can consider `A.depz` to be the
root of a tree of inclusions, and the effective value is found by doing a
breadth-first traversal of that tree.  If `myvalue` did not exist in
`A.depz`, the effective value would be from B (as B is the "leftmost" child
of A; e.g., the first one listed).  If it did not exist in B, it would be C
(as B and C are siblings).  If it did not exist in C, it would come from D
(as D is the deepest child).  If multiple configuration files are included on
the commandline, they are all siblings (in left to right order).

This order of precedence makes sense in general: if you include a project's
configuration file and it in turn includes a subproject, the "topmost"
project should generally have the ultimate say about configuration options.
However, there are cases where this may not be sufficient.  For example, a
project configuration file may with to TRY-INCLUDE a user's own config file
so that the user can customize their configuration.  Under normal rules,
this would mean that the project could not provide a default value, as
it would always have higher precedence.  Two special types of sections let
you address this type of situation: `DEFAULT` sections and `OVERRIDE`
sections.

Imagine that we altered the `A.depz` shown above so that instead of having
a `[mysection]` section, it had a `[DEFAULT mysection]` section (still
containing the same `myvalue` key).  This would change the effective value
of `[mysection].myvalue` to be "B's value".  Only if all of the other
configuration files (or at least their `myvalue` keys) were removed would
the value be "A's value", as values in `DEFAULT` sections have lower
precedence than ones in non-default values.  However, note that the precedence
of `DEFAULT` sections is the same as any section; if `B.depz` also had
a `[DEFAULT mysection]` section, it would have even lower precedence than
the `[DEFAULT mysection]` in `A.depz`.

`OVERRIDE` sections are the conceptual opposite.  Values in `OVERRIDE`
sections take precedence over values in normal (or `DEFAULT`!) sections.
Moreover, _the precedence of override sections themselves is reversed_.  That
is to say, that if both `A.depz` and `D.depz` have an `[OVERRIDE mysection]`
section, it is the one in `D.depz` which takes ultimate precedence.

## Parent and Child Sections

Along with all of the default and overriding mentioned in the previous
section, configuration files support parent and child sections.  Let's
consider the following example:
```
[MyParent]
key1=key1 from parent
key2=key2 from parent

[MyParent MyChild1]
key1=key1 from child1
key2=key2 from child1

[MyParent MyChild2]
key2=key2 from child2
key3=key3 from child2
```

"MyParent" is, in fact, just a normal section, and it is subject to the same
rules as usual concerning defaults and overrides.  Because its name is used
as a prefix for "MyChild1" (and "MyChild2", for that matter) it serves as its
parent section.  This means that "MyChild1" inherits values from "MyParent".
If there is overlap between their keys, the child keys take precedence.  Thus,
the effective values for "MyChild1" are as follows:

| Key   | Value                   |
|-------|-------------------------|
| key1  | key1 from child1        |
| key2  | key2 from child1        |

And the effective values for "MyChild2" are as follows:

| Key   | Value                   |
|-------|-------------------------|
| key1  | key1 from parent        |
| key2  | key2 from child2        |
| key3  | key3 from child2        |

## Value Substitution

Values can incorporate other values.  Consider the following config file:
```
[GLOBALS]
timeofday=morning

[favorites]
food=spam
weather=sunny

[phrases]
greeting=Good ${timeofday}
introduction=${greeting}!  Lovely day to eat some ${favorites:food}!
```

Besides noting the basic value substitution syntax, there are a couple other
quick points to be made.  First, a value can include a value that includes
another value (as `introduction` includes `greeting` which includes
`timeofday`).  Second, you can always refer to other keys within the same
section or keys within the special `GLOBALS` section by just using their
name.  Third, you can refer to keys in arbitrary other sections by prefixing
the key with the section name and separating the two with a colon.

### Special Values

Besides all of the values which actually exist within the configuration files
being processed, there are a number of special values that you can refer to.

| Name              | Meaning                                                 |
|-------------------|---------------------------------------------------------|
| \_FULL\_NAME\_    | The full name of the section in which the key appears   |
| \_NAME\_          | The name of the key's section (not including a prefix)  |
| \_KEY\_           | The name of the key                                     |
| \_FILE\_          | The filename of the file in which the key was defined   |
| \_DIR\_           | Just the directory part of the above                    |
| \_SECTION\_FILE\_ | Filename of the first file defining the key's section   |
| \_SECTION\_DIR\_  | Just the directory part of the above                    |

To elaborate a bit further: \_FULL\_NAME\_ is, indeed, the full name of the
key's section.  This is often going to be the same as it's \_NAME\_, but if
the section has a space in it, e.g., `REPO foo`, then \_NAME\_ is simply
`foo`, where \_FULL\_NAME\_ is `REPO foo`.  In other words, if you have
parent/child sections as described in the relevant section above, the name
gives the child-specific portion of the name, and the full name includes the
name of the parent as well.

\_FILE\_ and \_DIR\_ refer to the file where the effective value actually
comes from.  This may not be the same for each key in a section, as different
keys may be specified in different files within the same section (or via the
corresponding `OVERRIDE` and `DEFAULT` sections).  \_SECTION\_FILE\_ and
\_SECTION\_DIR\_ work differently.  They give the filename (or directory name)
of the first file where the section was defined according to the breadth-first
starting-from-root algorithm described in the section above about section
ordering.

That is, consider the following two configuration files.

A.depz:
```
[INCLUDE B.depz]

[mysection]
a_value=Value comes from ${_FILE_}
another_a_value=Value comes from ${_SECTION_FILE_}

```

B.depz
```
[mysection]
b_value=Value comes from ${_FILE_}
another_b_value=Value comes from ${_SECTION_FILE_}
```

In this case, `[mysection].a_value` would be "Value comes from A.depz",
and `[mysection].b_value` would be "Value comes from B.depz".  On the
other hand, both of the "another" values would refer to `A.depz`, since
`[mysection]` is first defined in `A.depz`.

# Configuring Repositories

To have depz manage a repository, you create a section for the repository in
a configuration file.  The section should be a child section of the parent
"REPO".  Here are the keys in REPO sections that depz actually looks at:

| Key               | Meaning                                               |
|-------------------|-------------------------------------------------------|
| full\_directory   | The local directory in which the repository will live |
| checkout          | The branch or tag to be checked out initially         |
| checkout\_remote  | List of git remotes from which to try getting the repo|
| group             | Allows for grouping repos together                    |
| monitor\_branch   | Local branches to monitor for changes                 |
| update\_skip      | When set, don't include this repo when doing --update |
|fast\_forward\_skip| When set, don't include when doing --fast-forward     |
| no\_tags          | Don't download normal tags                            |
| type              | Repository type (currently only git)                  |
| remote <foo>      | Configures a git remote for the repo                  |
| init\_archive etc.| An archive to use to initialize the repository        |

Some notes:

* `checkout` is the branch to check out initially.  This is often "master".
* `checkout_remote` is a list of names o remote to use when first trying to
   get the code.  In simple cases, this might be "origin".  The remote
   itself should be configured with a corresponding key, such as
   "remote origin".  depz will try each in turn until it succeeds; this way
   you can easily set multiple remotes, not all of which will necessarily
   work immediately (e.g., you may want to clone from your own personal fork
   if it exists, but fall back to an upstream repository otherwise).
* `group` is a list of group names.  This lets you group repos.  When depz
   is executed, it defaults to the group "default" and ignores any repo which
   does not list "default" in its groups.  This can be overridden with the
   `--group` commandline option.  This allows you to, for example, have a
   "libraries" group or a "mycompany" group and let you easily act on them
   independently.
* `monitor_branch` specifies a list of local branches which depz can monitor
   for changes (and potentially fast-forward) similar to how it monitors
   remotes.  The intended use case is if your workflow involves pushing into
   the local repository and not always just pulling from remotes.
* `update_skip` and `fast_forward` skip make it so that depz will ignore
   this repository when executing `--update` and `--fast-forward`.
* `no_tags` turns off tag downloading.  Note that depz *always* downloads
   remote git tags into a special set of remote\_tags refs.  This option
   refers to the normal operation of tags.
* `type` is currently always git.  Even for Mercurial and Bazaar
   repositories (see the sections on Mercurial and Bazaar later).
* If a key is two words and the first is `remote`, this defines a git remote.
  The second word of the key is the remote name, and the value should be the
  remote's URL.
* `init_archive` (and its related keys) are described in the next subsection.

To make things a bit easier to use and more flexible, depz sets up some
defaults and other keys which are inherited by all repos.  This is done
essentially by including the following "magical" section:
```
[DEFAULT REPO]
type=git

name=${_NAME_}
remote_name=${name}

remote origin=${prefix}/${remote_name}
checkout=master
checkout_remote=mine,origin,upstream
no_tags=False

directory=${name}
base_directory=${_SECTION_DIR_}
full_directory=${base_directory}/${directory}
group=default

fast_forward_skip=False
update_skip=False

monitor_branch=
```

While you can certainly just set the actual keys listed in the table above,
the defaults can be quite useful.  For example, the `full_directory` key is
built automatically from, essentially, the directory of your config file and
the name of the repository as defined by its section header name.  Thus, if
your section is `[REPO pox]`, and you want the directory to be called `pox`
and in the same directory as your `.depz` config file... you don't have to
do anything!

Similarly, it is very common that your local repository name should match
the remote repository name, and that is often (and always, on github) the
last part of the remote URL.  The default setting of `remote origin` makes
this simple, as it is composed of `prefix` and `remote_name`.  The latter
defaults to the local name (which defaults to the section name).  So all
you need to do is set the former.

Thus, a config file for the Rogue programming language's compiler, for
example, might look like this:
```
[REPO rogue]
prefix=https://github.com/AbePralle
```

That's enough to get started!

To see how this works, it may be useful to manually "merge in" some of the
settings which are included automatically from the `[DEFAULT REPO]` section
shown above (note that you don't have to actually do this; it is shown here
only for illustration):
```
[REPO rogue]
name=${_NAME_}
remote_name=${name}
remote origin=${prefix}/${remote_name}
checkout=master
```

If we wanted to add another remote, it's a simple matter of adding an
appropriate `remote` key:
```
remote murphymc=https://github.com/MurphyMc/rogue
```

Or perhaps:
```
remote murphymc=https://github.com/MurphyMc/${remote_name}
```

## Using Deploy Keys

GitHub has a feature called Deploy Keys which let you set ssh keys that are
specific to an individual repository.  These keys can be set to be read only
or read/write.  This is a nice way to have fine grained access to private
repositories from not-especially-trusted machines without having to store
real credentials on the remote machine or use wildly unsafe ssh agent
forwarding.

Deploy keys are specific to a given remote (thus, you can have different
deploy keys for different remotes, i.e., one for your organization's
fork and one for your own fork).  You enable them by setting the
`deploy_key <remote-name>` key in your repo config to `true`.  Thus, you
might have a config file like:
```
[REPO pox]
remote upstream=git@github.com:noxrepo/pox
deploy_key upstream=true
prefix=https://github.com/YourNameHere
```

Note that in this case, it's the `upstream` remote that is using a deploy key.
If you wanted to do it with the remote set up by the `prefix` key, you'd use
`deploy_key origin=true`.  See the previous section if you need a reminder
why this is the case.

Also note that the remote _must be using an ssh URL_ because deploy keys are
ssh keys!  An http/https URL won't work.

Once you have this set, running `--init` will now generate a new key pair
for the remote called `depz_deploy_key.upstream.private` and
`depz_deploy_key.upstream.pub` (where `upstream` will be whatever the
remote is named).  These are stored in the repository base directory.  If
run in interactive mode, before trying to fetch the remote for the first
time, depz will display the public key and pause until you press enter.
At this point, you can do one of two things:

* Copy and paste the public key into the repository's configuration on
  GitHub.  The URL to the appropriate configuration page is hopefully
  shown.
* Replace the new key pair with a key pair of your own.  If you've
  already got one you want to use, this makes sense, but see the next
  subsection.

Note that depz adds files matching the pattern `depz_deploy_key.*` to the
repository's `exclude` file in order to help you _not commit these to the
repo_, because you really probably don't want to do that.

From now on, depz will try to use these key files when communicating with
the specified remote.

### Using a Pre-Existing Key Pair

The previous example showed how to get depz to generate a new key pair
for you by setting the `deploy_key <remote-name>` entry to `true`.  You
can also set this entry to the base filename of an existing key pair.
If you do this, during `--init`, depz will take that base filename,
append `.pub` and `.private` to it, and _copy_ those files into the
repository to the appropriate `depz_deploy_key.*` files.

### Using Deploy Keys with Manual Git

While depz knows to use the deploy keys, git itself doesn't if you just run
git commands by hand.  You can refer to the Internet to see how to configure
git to use an arbitrary key file -- there are several ways, both via
messing with ssh's config or via messing with git's config.

One way to do it -- which only really makes sense if you have a single
ssh remote -- is to configure the repository to always try to use the deploy
key when doing ssh.  This is basically a matter of setting the `sshCommand`
git configuration property to a commandline for ssh that includes the `-i`
option to specify a key.  To save you the effort, the depz `--set-ssh-cmd`
option does exactly this.  After this, git commands in this repository
which use ssh remotes should use the deploy key.  However, note that
the `sshCommand` configuration key is only available in git 2.10 and
above.  If you're using an older version of git, you'll have to work
out another solution.

## Initializing a Repository from an Archive

Sometimes you want a project to use code that's available in an archive file
(like a .zip or .tgz) somewhere, but may not be available already in a code
repository that you have access to.  You could just download it into your main
project repository, though that's not particularly elegant.  You could
download it, create a new github project, add all the files, and push it to
github, but this seems a bit over the top especially if you're not planning
to actually make any changes to it.

To deal with this situation, you can give depz the URL to an archive and it
will download it and initialize the repository to its contents.  If you've
got remotes set, you could then push it to a new repository somewhere else
(e.g., github), or you can just keep it locally.  Since it actually creates
a new repository containing the initial files, if you *do* end up changing
anything, your changes are already tracked from the start.

To enable this functionality, you must at least set the `init_archive` key to
the URL of the archive file.  Exactly what types of URLs and what types of
archives will work depends on your version of Python, but it's really likely
that `http`, `https`, `zip`, and `tgz`/`tar.gz` will work.

In addition, you can set the `init_archive_sha1`, `init_archive_sha256`, or
`init_archive_sha512` keys to the correct hash of the archive, and depz
will check that they are correct before expanding the archive to help
ensure that you get the files you intended.  _This is a very good idea and
you should do it._

## Using Mercurial Repositories

Currently, depz only _really_ works with git.  However, Mercurial
repositories can be made to work fairly transparently within git via
git-remote-hg.  This seems to be enough to make them work well within
depz, though it has not been tested extensively.  On Ubuntu (and probably
Debian), you can install git-remote-hg with:
```
sudo apt install git-remote-hg
```

When specifying a repository in a config file, simply preface the remote
URL with "hg::", like:
```
[REPO SDL_mixer]
checkout=release-1.2.12
prefix=hg::https://hg.libsdl.org
```

## Using Bazaar Repositories

Again, depz currently only works directly with git.  However, similar to how
git-remote-hg provides transparent access to Mercurial repositories from
within git, git-remote-bzr provides similar functionality for Bazaar.  Thus,
there is hope that one could use Bazaar repositories with depz by installing
git-remote-bzr, and configuring remote URLs with the "bzr::" prefix.  This has
been tested even less than Mercurial, but at least the following example seems
to work.

Install git-remote-bzr:
```
sudo apt install git-remote-bzr
```

An example config for the GRUB bootloader:
```
[REPO grub]
checkout=people+gsutre+fixes
prefix=bzr::bzr://bzr.savannah.gnu.org/grub
```
