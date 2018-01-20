# SSP21

Secure SCADA Protocol for the 21st century (SSP21) is a cryptographic wrapper for ICS environments. It is inspired by
the [Noise Protocol](http://noiseprotocol.org/).

# Specification

The specification is built using [pandoc](http://pandoc.org/). The included Makefile will generate PDF and HTML output.

# Setup
Different operating systems require different procedures.
## Linux

```
> sudo apt-get install pandoc mscgen graphviz texlive texlive-latex-base texlive-fonts-recommended lmodern python-dev python-pip inkscape
> pip install pandoc-fignos
```
Depending on your setup of Python, you may need to add `~/.local/bin` to your path.
## macOS
The steps below have been tested succesfully on macOS High Sierra and leverage the [pip](https://pypi.python.org/pypi/pip) as well as [Homebrew](https://brew.sh) package managers, the latter with its cask extension. Each of the commands installs a required package, if not present yet. Note that this includes `mactex`, which is a 3 GB download. It might be possible to use a lightweight version of TeX but that has not been tested.

```
> brew cask install xquartz
> brew cask install inkscape
> brew cask install mactex
> brew install pandoc mscgen graphviz
> pip install pandoc-fignos
```
If  not yet present in the path, add `/Library/TeX/Root/bin/x86_64-darwin`, using something like `PATH=$PATH:/Library/TeX/Root/bin/x86_64-darwin`. Running `make` should yield the desired result.