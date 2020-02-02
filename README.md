# aiobroadlink
Library to control various Broadlink devices using asyncio


This software is based on the protocol description from Ipsum Domus (?)
Details at https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1

This software is based on python-broadlink by Matthew Garrett
Details at  https://github.com/mjg59/python-broadlink

This is a very early version. Remote Control device seem to be working alright (both IR and RF)

A1 device also work.

Provisioning works.

RM4C can be provisioned and detected, but does not seem to accept commands.

Other will be tested soon.

You can run

    python3 -m aiobroadlink

If your IP address cannot be guessed, do

    python3 -m aiobroadlink -i xxx.xxx.xxx.xxx

with xxx.xxx.xxx.xxx the IP address of the interface you want to use.

