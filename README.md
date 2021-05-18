# aiobroadlink
Library to control various Broadlink devices using asyncio


This software is based on the protocol description from Ipsum Domus (?)
Details at https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1

This software is based on python-broadlink by Matthew Garrett
Details at  https://github.com/mjg59/python-broadlink

Remote Control device seem to be working alright (both IR and RF)

RM4C are now supported.
RM4 PRO are also supported.

A1 device also work.

Provisioning works.

Other will be tested when I get the relevant hardware.

Install with pip3. Be forewarned that aiobroadlink needs the 'cryptography' library.
This library will be automatically installed, but for this to succeed, you do need to
be able to compile things. To that effect you need a compiler and some header files. On
Debian/Ubuntu distributions, this means you need the packages 'libffi-dev' and 'libssl-dev'

You can run

    aiobroadlink

or

    python3 -m aiobroadlink

If your IP address cannot be guessed, do

    aiobroadlink -i xxx.xxx.xxx.xxx

with xxx.xxx.xxx.xxx the IP address of the interface you want to use.

When learning commands, they will be save in the file ~/.aiobroadlink.
