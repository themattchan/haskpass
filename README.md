# haskpass

haskpass is a 1Password client for Linux, inspired
by and mostly a clone of [gonepass](https://github.com/themattchan/gonepass),
just so I don't have to deal with C++.

### Building

Install dependencies

```
sudo dnf install gtk2-devel gtksourceview2-devel glib2-devel ghc-gtk-devel
stack install gtk2hs-buildtools
```

Build

```
stack build
stack install
```
