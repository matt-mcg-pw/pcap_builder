# Overview
Gathering, collecting, creating and hacking PCAPs is a large consumer of time
and can be a great causer of confusion and frustration when writing integration
tests.  This package will help to make PCAP creation and manipulation more
convenient, usable and abstracted so that working with PCAPs is more intuitive
for developers and test authors.

## Initial Dev Notes / Architecture Thoughts / Expected Use Cases
- Add TCP Handshakes (Syn / Ack, Fin / Ack) to both sides of transaction
- Modify any field in any packet of the full capture

## Initial Pitfalls / Things to Document / Consider
#### Installing Scapy for Python3 on OS X
? Can this be handled in setup.py ?
- This can be troublesome
- Scapy needs to run python as a framework
- We use _pyenv_ to manage Python versions
- `Matplotlib` has good docs on working around this
    - Matplotlib on OS X https://matplotlib.org/faq/osx_framework.html
    - `PYTHON_CONFIGURE_OPTS="--enable-framework" pyenv install x.x.x`
- Use _Homebrew_ to install _libdnet_
    - `brew install libdnet`
- Python packages required are installed with _setuptools_ from package root dir
    - `python setup.py [install|develop]`