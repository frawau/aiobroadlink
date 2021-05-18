#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This library is for the control of Broadlink devices
#
# Copyright (c) 2020 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE
#
# This software is based on the protocol description from Ipsum Domus (?)
# Details at
#   https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
#
# This software is based on python-broadlink by Matthew Garrett
# Details at
#   https://github.com/mjg59/python-broadlink
#
import asyncio as aio
import datetime as dt
import codecs, logging, random, socket, ipaddress, os, time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMANDS = {
    "Hello": [0x6, 0x7],
    "Discover": [0x1A, 0x1B],
    "Join": [0x14, 0x15],
    "Auth": [0x65, 0x3E9],
    "Command": [0x6A, 0x3EE],
}

TIMEOUT = 7  # seconds. After this Timeout
DSTEPS = 10  # seconds. Decrement value and sleep time between discovery runs.


class Message:
    """Class defining a message;

       Creating a message requires only a device and a command
       (A key in the COMMANDS dictionary)

       Other parameter can be set afterward
            payload
            encrypt: True or False encrypt the message or not
            cb       A callback function
            multiple: True or False. Expect multiple answers or not

    """

    def __init__(self, dev, cmd):
        self.device = dev
        self.cmd = COMMANDS[cmd][0]
        self.payload = bytearray(0)
        self.encrypt = True
        self.cb = None
        self.ret = COMMANDS[cmd][1]
        self.public = False
        self.multiple = False


class BroadlinkDevice:
    """ Generic Broadlink device. As-is it can be used to broadcast Hello messages
    """

    def __init__(self, devtype, name="Broadlink", cloud=False):
        self.init_vect = bytearray(
            b"\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58"
        )
        self.init_key = bytearray(
            b"\x09\x76\x28\x34\x3f\xe9\x9e\x23\x76\x5c\x15\x13\xac\xcf\x8b\x02"
        )
        self.connect_id = bytearray(b"\xa5\xaa\x55\x5a\xa5\xaa\x55\x00")
        self.key = self.update_aes(self.init_key)
        self.id = bytearray(4)
        self.dev_type = devtype
        self.dev_id = 0
        self.dev = "Generic"
        self.mac = "00:00:00:00:00:00"
        self.ip = "255.255.255.255"
        self.name = name[:32]
        self.cloud = False
        self.count = 0
        self.controller = None
        self.result = aio.Queue()
        self.is_auth = False

    def __str__(self):
        return self.name + " " + "@" + self.ip + " (".self.mac + ") "

    @property
    def next(self):
        """Increase and retturn the message count for this device"""
        self.count += 1
        return self.count

    def update_aes(self, key):
        """Reconfigure the encryption key """
        return Cipher(
            algorithms.AES(key), modes.CBC(self.init_vect), backend=default_backend()
        )

    def encrypt(self, payload):
        """Encrypt the payload"""
        encryptor = self.key.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def decrypt(self, payload):
        """Decrypt the payload"""
        decryptor = self.key.decryptor()
        return decryptor.update(payload) + decryptor.finalize()

    def register(self, control):
        """Associate the device with a BroadlinkProtocol controller"""
        self.controller = control

    @property
    def iptobytes(self):
        return int(ipaddress.IPv4Address(self.ip)).to_bytes(4, "little")

    @staticmethod
    def bytestoip(ip):
        """Transform a buffer of bytes (little endian) into an IPv4 address"""
        return str(ipaddress.IPv4Address(bytes(ip[::-1])))

    @property
    def mactobytes(self):
        """Transform a MAC address string into a list of bytes (little endian)"""
        return codecs.decode("".join(self.mac.split(":")[::-1]).encode(), "hex")

    @staticmethod
    def bytestomac(mac):
        """Transform a lisat of bytes (little endian) in to a MAC address string"""
        return ":".join(["%02x" % x for x in mac[::-1]])

    def hello(self, ip, port):
        """Send the Hello message to discover devices on the network

        The parameter are:
             ip: a string representing an IPv4 address
                 this is the address of the interfaced
                 used to broadcast the message.
             port: an int representing the port used by
                   the socket usaed to communicate

        """
        if self.ip not in ["255.255.255.255"]:
            logging.critical(
                "Error: this device can not be used to send Hello messages"
            )
            return
        logging.debug("Sending Hello")
        message = Message(self, "Hello")
        payload = bytearray(40)
        tzo = int(time.timezone / -3600)
        payload[0:4] = tzo.to_bytes(4, byteorder="little")
        now = dt.datetime.now()
        payload[4:6] = now.year.to_bytes(2, byteorder="little")
        payload[6] = now.second
        payload[7] = now.minute
        payload[8] = now.hour
        payload[9] = now.isoweekday()
        payload[10] = now.day
        payload[11] = now.month
        payload[16:20] = int(ipaddress.IPv4Address(ip)).to_bytes(4, "little")
        payload[20:22] = port.to_bytes(2, byteorder="little")
        message.payload = payload
        message.encrypt = False
        message.multiple = True
        message.cb = self.hello_cb
        self.controller.send_message(message)

    def hello_cb(self, resp):
        """Handle the devices reply to the Hello command. It will look at
        messages and created devices accordingly. The newly crerated devices are then
        return via the Queue to the caller"""
        dev_type = int.from_bytes(resp[52:54], byteorder="little", signed=False)
        ip = self.bytestoip(resp[54:58])
        mac = self.bytestomac(resp[58:64])
        desc = bytearray(0)
        length = len(resp[64:])
        for x in range(length):
            if resp[64 + x] == 0:
                break
            desc.append(resp[64 + x])
        desc = desc.decode("utf-8")
        cloud = bool(resp[-1])
        newdev = gen_device(dev_type, ip, mac, desc, cloud)
        self.result.put_nowait(newdev)

    def auth(self):
        """handle the device authentication."""
        message = Message(self, "Auth")
        payload = bytearray(80)
        rkey = b"\x31" * 15 + b"\x00"
        payload[4:20] = rkey
        payload[30] = 1
        payload[45] = 1
        name = "Test  1"
        payload[48 : 48 + len(name)] = self.name.encode("utf-8")
        message.payload = payload
        message.cb = self.auth_cb
        self.controller.send_message(message)

    def auth_cb(self, resp):
        """Handles the devices reply to the authentication command,
        updates the key according to the key provided by the device.

        Returns True or False to the caller via the Queue.
        """
        if self.check_noerror:
            payload = self.decrypt(resp[56:])
            self.key = self.update_aes(payload[4:20])
            self.dev_id = int.from_bytes(payload[0:4], byteorder="little", signed=False)
            self.is_auth = True
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def join(self, ssid, password="", security="wpa2"):
        """Configure a device to join a WiFi networkd. Command side.
         ssid is the SSID to join
         password is the passphrase to use
         security must be one of none, wep, wpa1, wpa2, wpa1/2
        """
        logging.debug("Sending Join")
        message = Message(self, "Join")
        message.public = True
        payload = bytearray(60)
        payload = payload + bytearray([ord(x) for x in ssid])
        payload = payload + bytearray(92 - len(payload))
        payload = payload + bytearray([ord(x) for x in password])
        payload = payload + bytearray(128 - len(payload))
        payload[124] = len(ssid)
        payload[125] = len(password)
        sec = ["none", "wep", "wpa1", "wpa2", "wpa1/2"].index(security.lower())
        if not sec and len(password):
            sec = 4
        payload[126] = sec
        message.payload = payload
        message.cb = self.join_cb
        self.controller.send_message(message)

    def join_cb(self, resp):
        """Configure a device to join a WiFi networkd. Reply side."""
        if self.check_noerror:
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def check_noerror(self, resp):
        """Check if the return code is OK"""
        err = int.from_bytes(resp[34:36], byteorder="little", signed=False)
        if err != 0:
            logging.debug("Error: Device returned error {}.".format(err))
            return False
        return True

    async def authenticate(self):
        """Convenience courotine to perform authentication."""
        self.auth()
        try:
            resu = await aio.wait_for(self.result.get(), timeout=5.0)
        except aio.TimeoutError:
            logging.debug("No answer to auth")
            return False
        return resu

    async def provision(self, ssid, password="", security="wpa2"):
        """Convenience coroutine to provision devices.
            ssid is the SSID to join
            password is the passphrase to use
            security must be one of none, wep, wpa1, wpa2, wpa1/2
         """
        self.join(ssid, password, security)
        try:
            resu = await aio.wait_for(self.result.get(), timeout=5.0)
        except aio.TimeoutError:
            logging.debug("No answer to join")
            return False
        return resu


class rm(BroadlinkDevice):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(devtype, name=name, cloud=cloud)
        self.ip = ip
        self.mac = mac
        self.dev = "RM"
        self._request_header = bytes()
        self._code_sending_header = bytes()

    def check_data(self):
        """Retrieve data leant by the device. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header + b"\x04")
        message.cb = self.check_data_cb
        self.controller.send_message(message)

    def check_data_cb(self, resp):
        """Retrieve the data learnt by the device. Reply Side"""
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            self.result.put_nowait(payload[len(self._request_header) + 0x04 :])
        else:
            self.result.put_nowait(False)

    def send_data(self, data):
        """Request device to send IR/RF codes. Command side"""
        message = Message(self, "Command")
        payload = bytearray(self._code_sending_header) + bytearray(
            [0x02, 0x00, 0x00, 0x00]
        )
        payload += data
        message.payload = payload
        message.cb = self.send_data_cb
        self.controller.send_message(message)

    def send_data_cb(self, resp):
        """Check that code was sent. Reply side"""
        logging.debug("Got answer to send_data: {}".format(resp))
        if self.check_noerror(resp):
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def enter_learning(self):
        """Start learning an IR code. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x03")
        message.cb = self.enter_learning_cb
        self.controller.send_message(message)

    def enter_learning_cb(self, resp):
        """Learning an IR code. Reply side"""
        logging.debug("Got answer to enter_learning: {}".format(resp))
        if self.check_noerror(resp):
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def check_temperature(self):
        """Retrieve sensor information. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x01")
        message.cb = self.check_temp_cb
        self.controller.send_message(message)

    def check_temp_cb(self, resp):
        """Retrieve sensor information. Reply side"""
        temp = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            offset = len(self._request_header) + 0x04
            temp = (payload[offset] * 10 + payload[offset + 1]) / 10.0
        self.result.put_nowait(temp)

    async def temperature_check(self, timeout=5):
        """Conveenience coroutine to retrieve sesor data"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        self.check_temperature()
        try:
            temp = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got temperature {}’C".format(temp))
            return temp
        except aio.TimeoutError:
            logging.debug("No answer to check_temperature")
            return None

    async def learn_ir_code(self, timeout=10):
        """Convenience coroutine to learn IR code"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        logging.debug("Learning IR")
        self.enter_learning()
        try:
            tmp = await aio.wait_for(self.result.get(), timeout=5.0)
        except aio.TimeoutError:
            logging.debug("No answer to enter_learning")
            return None

        end = dt.datetime.now() + dt.timedelta(seconds=timeout)
        code = False
        while dt.datetime.now() <= end:
            await aio.sleep(1)
            self.check_data()
            try:
                code = await aio.wait_for(self.result.get(), timeout=3.0)
            except aio.TimeoutError:
                logging.debug("No answer to check_data")

            if code:
                logging.debug("Got code {}".format(code))
                return code
        if not code:
            logging.debug("Could not get data")
            return None

    async def send_code(self, code, timeout=5):
        """Convenience coroutine to request the device to issue
        a giiven IR/RF code.

        The parameter is the code to sent

        """
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False
        self.send_data(code)
        resu = False
        try:
            resu = await aio.wait_for(self.result.get(), timeout=timeout)
        except aio.TimeoutError:
            logging.debug("No answer to send_data")

        return resu


class rmp(rm):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(ip, mac, devtype, name)
        self.dev = "RM PRO"
        self._request_header = bytes()
        self._code_sending_header = bytes()

    def sweep_frequency(self):
        """Search for RF frequency carrier. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x19")
        message.cb = self.sweep_frequency_cb
        self.controller.send_message(message)

    def sweep_frequency_cb(self, resp):
        """Search for RF frequency carrier. Reply side"""
        logging.debug("Got answer to sweep_frequency: {}".format(resp))
        if self.check_noerror(resp):
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def cancel_sweep_frequency(self):
        """Cancel search for RF frequency carrier. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x1e")
        message.cb = self.cancel_sweep_frequency_cb
        self.controller.send_message(message)

    def cancel_sweep_frequency_cb(self, resp):
        """Cancel search for RF frequency carrier. Reply side"""
        logging.debug("Got answer to cancel_sweep_frequency: {}".format(resp))
        if self.check_noerror(resp):
            self.result.put_nowait(True)
        else:
            self.result.put_nowait(False)

    def check_frequency(self):
        """"Check if carrier has been acquirted. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x1a")
        message.cb = self.check_frequency_cb
        self.controller.send_message(message)

    def check_frequency_cb(self, resp):
        """"Check if carrier has been acquirted. Reply side"""
        if self.check_noerror(resp):
            #payload = self.decrypt(bytes(resp[56:]))
            #if payload[len(self._request_header) + 0x04] == 1:
            self.result.put_nowait(True)
            return
        self.result.put_nowait(False)

    def find_rf_packet(self):
        """"Rertrieve learnt RF code. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x1b")
        message.cb = self.find_rf_packet_cb
        self.controller.send_message(message)

    def find_rf_packet_cb(self, resp):
        """"Rertrieve learnt RF code. Reply side"""
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            if payload[len(self._request_header) + 0x04] == 1:
                self.result.put_nowait(True)
                return
        self.result.put_nowait(False)

    async def learn_rf_code(self, timeout=10, cb=None, lock=None):
        """A convenience coroutine to learn a RF code.

        The learning of a RF code is done in 2 steps:
            1: Lock onto the carrier
            2: Learn the code

        Since it may be necessary to indicate to the user the change of
        step. To that effect 2 parameters are provided.

            cb: a callback coroutine that will be awaited midway through the process
            lock:  An asyncio.Lock that needs to be acquired before one can proceed.
        """
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        logging.debug("Learning RF")
        self.sweep_frequency()
        end = dt.datetime.now() + dt.timedelta(seconds=timeout)
        code = False
        while dt.datetime.now() <= end:
            await aio.sleep(1)
            self.check_frequency()
            try:
                code = await aio.wait_for(self.result.get(), timeout=3.0)
            except aio.TimeoutError:
                logging.debug("No answer to check_frequency")
        if not code:
            self.cancel_sweep_frequency()
            try:
                code = await aio.wait_for(self.result.get(), timeout=5.0)
            except aio.TimeoutError:
                pass
            return False

        if cb:
            await cb()

        if lock:
            await lock.acquire()
            lock.release()
        self.find_rf_packet()
        try:
            tmp = await aio.wait_for(self.result.get(), timeout=5.0)
        except aio.TimeoutError:
            logging.debug("No answer to find_rf_packet")
            return None

        end = dt.datetime.now() + dt.timedelta(seconds=timeout)
        code = False
        while dt.datetime.now() <= end:
            await aio.sleep(1)
            self.check_data()
            try:
                code = await aio.wait_for(self.result.get(), timeout=3.0)
            except aio.TimeoutError:
                logging.debug("No answer to check_data")

            if code:
                logging.debug("Got code {}".format(code))
                return code
        if not code:
            logging.debug("Could not get data")
            return None


class rm4(rm):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(ip, mac, devtype, name)
        self.dev = "RM4"
        self._request_header = b"\x04\x00"
        self._code_sending_header = b"\xd0\x00"

    def check_temperature(self):
        """Retrieve sensor information. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x24")
        message.cb = self.check_temp_cb
        self.controller.send_message(message)

    def check_temp_cb(self, resp):
        """Retrieve sensor information. Reply side"""
        temp = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            offset = len(self._request_header) + 0x04
            temp = (payload[offset] * 10 + payload[offset + 1]) / 10.0
        self.result.put_nowait(temp)

    async def temperature_check(self, timeout=5):
        """Conveenience coroutine to retrieve sesor data"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        self.check_temperature()
        try:
            temp = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got temperature {}’C".format(temp))
            return temp
        except aio.TimeoutError:
            logging.debug("No answer to check_temperature")
            return None

    def check_humidity(self):
        """Retrieve sensor information. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(self._request_header) + bytearray(b"\x24")
        message.cb = self.check_humid_cb
        self.controller.send_message(message)

    def check_humid_cb(self, resp):
        """Retrieve sensor information. Reply side"""
        temp = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            offset = len(self._request_header) + 0x06
            temp = (payload[offset] * 10 + payload[offset + 1]) / 10.0
        self.result.put_nowait(temp)

    async def humidity_check(self, timeout=5):
        """Conveenience coroutine to retrieve sesor data"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        self.check_humidity()
        try:
            temp = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got humidity {}%".format(temp))
            return temp
        except aio.TimeoutError:
            logging.debug("No answer to check_humidity")
            return None


class rm4p(rm4, rmp):
    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(ip, mac, devtype, name)
        self.dev = "RM4 PRO"


class a1(BroadlinkDevice):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(devtype, name=name, cloud=cloud)
        self.ip = ip
        self.mac = mac
        self.dev = "A1"

    def check_sensors(self):
        """Retrieve sensor information. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(b"\x01" + b"\x00" * 15)
        message.cb = self.check_sensors_cb
        self.controller.send_message(message)

    def check_sensors_cb(self, resp):
        """Retrieve sensor information. Reply side"""
        resu = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            data = {}
            payload = self.decrypt(bytes(resp[0x38:]))
            if isinstance(payload[4], int):
                data["temperature"] = (payload[4] * 10 + payload[5]) / 10.0
                data["humidity"] = (payload[6] * 10 + payload[7]) / 10.0
                light = payload[8]
                air_quality = payload[10]
                noise = payload[12]
            else:
                data["temperature"] = (ord(payload[4]) * 10 + ord(payload[5])) / 10.0
                data["humidity"] = (ord(payload[6]) * 10 + ord(payload[7])) / 10.0
                light = ord(payload[8])
                air_quality = ord(payload[10])
                noise = ord(payload[12])
            if light == 0:
                data["light"] = "dark"
            elif light == 1:
                data["light"] = "dim"
            elif light == 2:
                data["light"] = "normal"
            elif light == 3:
                data["light"] = "bright"
            else:
                data["light"] = "unknown"
            if air_quality == 0:
                data["air_quality"] = "excellent"
            elif air_quality == 1:
                data["air_quality"] = "good"
            elif air_quality == 2:
                data["air_quality"] = "normal"
            elif air_quality == 3:
                data["air_quality"] = "bad"
            else:
                data["air_quality"] = "unknown"
            if noise == 0:
                data["noise"] = "quiet"
            elif noise == 1:
                data["noise"] = "normal"
            elif noise == 2:
                data["noise"] = "noisy"
            else:
                data["noise"] = "unknown"

            resu = data

        self.result.put_nowait(resu)

    async def sensor_check(self, timeout=5):
        """Conveenience coroutine to retrieve sensor data"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return None
        self.check_sensors()
        try:
            data = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got sensors {}".format(data))
            if data:
                return data
            return None
        except aio.TimeoutError:
            logging.debug("No answer to check_temp")
            return None


class mp1(BroadlinkDevice):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False, nbsock=4):
        super().__init__(devtype, name=name, cloud=cloud)
        self.ip = ip
        self.mac = mac
        self.dev = "MP1"
        self.current_state = [0] * nbsock
        self.nbsock = nbsock

    def set_power(self, sid, state):
        """Set socket power state. Command side. Socket id start from 0. State is 1 for on, 0 for off"""
        message = Message(self, "Command")

        payload = bytearray(b"\x0d\xa5\xa5\x5a\x5a\xb2\xc0\x02\x03" + b"\x00" * 7)
        payload[6] += 1 << (sid + 1) if state else 1 << sid
        payload[13] = 1 << sid
        payload[14] = 1 << sid if state else 0
        message.payload = payload
        message.cb = self.set_power_cb
        self.controller.send_message(message)

    def set_power_cb(self):
        """Set socket power state. Reply side"""
        resu = False
        if self.check_noerror(resp):
            # payload = self.decrypt(bytes(resp[56:]))
            resu = True
        self.result.put_nowait(resu)

    def check_power(self):
        """Check socket power state. Command side."""
        message = Message(self, "Command")
        message.payload = bytearray(b"\x0a\xa5\xa5\x5a\x5a\xae\xc0\x01" + b"\x00" * 8)
        message.cb = self.check_power_cb
        self.controller.send_message(message)

    def check_power_cb(self, resp):
        """Set socket power state. Command side. Socket id start from 0. State is 1 for on, 0 for off"""
        resu = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            resu = [payload[4] & 0x1 << i and 1 for i in range(self.nbsock)]
            self.current_state = resu
        self.result.put_nowait(resu)

    async def power_set(self, sid, state, timeout=5):
        """Convenience coroutine to set the power of a socket. sid start from 0, state can be 1,0, on,off"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False
        if isinstance(state, int):
            mystate = state and 1
        elif isinstance(state, str):
            mystate = (state.lower() == "on" and 1) or 0
        else:
            logging.error(
                "Unexpected class for state {}. Turning socket off.".format(
                    state.__class__
                )
            )
            mystate = 0
        self.set_power(sid, mystate)
        resu = False
        try:
            resu = await aio.wait_for(self.result.get(), timeout=timeout)
        except aio.TimeoutError:
            logging.debug("No answer to set_power")
        return resu

    async def power_check(self, sid=None, timeout=5):
        """Convenience coroutine to check the current status of socket.
        The return value is "on" or "off". If sid is none all status are returned in an array"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False
        self.check_power()
        resu = False
        try:
            resu = await aio.wait_for(self.result.get(), timeout=timeout)
            if sid is not None:
                try:
                    resu = resu[sid] and "on" or "off"
                except:
                    logging.error("Error: Socket id {} is out of range.".format(sid))
            else:
                resu = [(x and "on") or "off" for x in resu]
        except aio.TimeoutError:
            logging.debug("No answer to check_power")
        return resu


class sp2(BroadlinkDevice):
    """Class for Broadlink remote control devices"""

    def __init__(self, ip, mac, devtype, name="Broadlink", cloud=False):
        super().__init__(devtype, name=name, cloud=cloud)
        self.ip = ip
        self.mac = mac
        self.nightmode = 0
        self.power = 0
        self.nextmode = None
        self.dev = "SP2"

    def set_power(self, state, nightmode=0):
        """Set device power mode. Command side, state and nightmode are 1 or 0"""
        message = Message(self, "Command")
        message.payload = bytearray(b"\x02" + b"\x00" * 15)
        message.payload[4] = (2 if nightmode else 0) + (1 if state else 0)
        message.cb = self.set_power_cb
        self.nextmode = [state, nightmode]
        self.controller.send_message(message)

    def set_power_cb(self, resp):
        """Set device power mode. Reply side"""
        resu = False
        if self.check_noerror(resp):
            # payload = self.decrypt(bytes(resp[56:]))
            resu = True
            if self.nextmode:
                self.power, self.nightmode = self.nextmode
        self.nextmode = None
        self.result.put_nowait(resu)

    def check_power(self):
        """Check socket state. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(b"\x01" + b"\x00" * 15)
        self.controller.send_message(message)

    def check_power_cb(self, resp):
        """Check socket state. Reply side"""
        resu = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            self.power = payload[4] & 0x1
            self.nightmode = payload[4] & 0x2
            resu = {"power": self.power, "nightmode": self.nightmode}
        self.result.put_nowait(resu)

    def check_energy(self):
        """Check energy. Command side"""
        message = Message(self, "Command")
        message.payload = bytearray(b"\x01\x00\xfe\x01\x05\x01\x00\x00\x00\x2d")
        message.cb = self.check_energy_cb
        self.controller.send_message(message)

    def check_energy_cb(self, resp):
        """Check energy. Reply side"""
        resu = False
        if self.check_noerror(resp):
            payload = self.decrypt(bytes(resp[56:]))
            evalue = int.from_bytes(payload[6:8], byteorder="little", signed=False)
            evalue += payload[5] / 100.0
            resu = evalue
        self.result.put_nowait(resu)

    async def power_set(self, state, nightmode, timeout=5):
        """Convenience coroutine to set the state of a device. state and nightmode can be 1,0, on,off"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False
        if isinstance(state, int):
            mystate = state and 1
        elif isinstance(state, str):
            mystate = (state.lower() == "on" and 1) or 0
        else:
            logging.error(
                "Unexpected class for state {}. Turning socket off.".format(
                    state.__class__
                )
            )
            mystate = 0

        if isinstance(nightmode, int):
            mynm = nightmode and 1
        elif isinstance(nightmode, str):
            mynm = (nightmode.lower() == "on" and 1) or 0
        else:
            logging.error(
                "Unexpected class for nightmode {}. Turning nightmode off.".format(
                    state.__class__
                )
            )
            mynm = 0

        self.set_power(sid, mystate, mynm)
        resu = False
        try:
            resu = await aio.wait_for(self.result.get(), timeout=timeout)
        except aio.TimeoutError:
            logging.debug("No answer to set_power")
        return resu

    async def power_check(self, timeout=5):
        """Convenience coroutine to check the state of a device. state and nightmode can be 1,0, on,off"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False

        self.check_power()
        try:
            data = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got power state {}".format(data))
            if data:
                return data
            return None
        except aio.TimeoutError:
            logging.debug("No answer to check_power")
            return None

    async def energy_check(self, timeout=5):
        """Convenience coroutine to check the state of a device. state and nightmode can be 1,0, on,off"""
        if not self.is_auth:
            resu = await self.authenticate()
            if not self.is_auth:
                logging.critical("Could not authenticate")
                return False

        self.check_energy()
        try:
            data = await aio.wait_for(self.result.get(), timeout=timeout)
            logging.debug("Got energy reading {}".format(data))
            if data:
                return data
            return None
        except aio.TimeoutError:
            logging.debug("No answer to check_energy")
            return None


class BroadlinkProtocol:
    """The networking part of the aiobroadlink library. This
    object serves as controller for all devices."""

    def __init__(self, process=None):
        self.waiting = (
            {}
        )  # A device keyed dictionary with ( code, callbacks , timestamp)
        self.devices = {}
        self.process = process
        self.transport = None
        self.stop_discovery = False

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def datagram_received(self, data, addr):
        """Receive a message from a device. Parses the message and figure out
        from which device it comes. If that device avatar is awaiting something, the associated
        callback, if set, will be called"""
        logging.debug(
            "data received: {}, {}".format(
                " ".join("0x{:02x}".format(c) for c in data), addr
            )
        )
        if len(data) < 48:
            logging.debug("Error: Data is too short")
            return
        data = bytearray(data)
        checksum = int.from_bytes(data[32:34], byteorder="little", signed=False)
        data[32:34] = bytearray(2)
        if checksum != self._checksum(data):
            logging.debug("Error: Wrong checksum")
            return

        devtype = int.from_bytes(data[36:38], byteorder="little", signed=False)
        respcode = int.from_bytes(data[38:40], byteorder="little", signed=False)

        logging.debug("Got rcode {}, device type {}".format(respcode, devtype))
        if respcode not in [x[1] for x in COMMANDS.values()]:
            logging.debug("Error: Unknown Response Code {c:04x}".format(c=respcode))
            return

        mac = BroadlinkDevice.bytestomac(data[42:48])
        logging.debug("Got mac {}".format(mac))
        logging.debug("Looking into {}".format(self.waiting))
        # Find the waititng host
        found = None
        for host in self.waiting:
            code, cb, tstamp, keep = self.waiting[host]
            if code == respcode and mac == host.mac:
                found = host
                cb(data)
                break
        if found and not keep:
            del self.waiting[host]

    def register(self, device):
        """Registering new devices"""
        if device.mac in self.devices:
            logging.debug("Known Device")
            if device.ip != self.devices[device.mac].ip:
                self.devices[device.mac].ip = device.ip
        else:
            logging.debug("New Device")
            self.devices[device.mac] = device
            device.register(self)
            if self.process:
                try:
                    self.process(device)
                except Exception as e:
                    logging.critical("User processing failed: {}".format(e))

    def unregister(self, device):
        """Unegistering a known devices"""
        if device.mac in self.devices:
            del self.devices[device.mac]
            if device in self.waiting:
                del self.waiting[device]

    def _checksum(self, payload):
        checksum = 0xBEAF
        for i in range(len(payload)):
            checksum += payload[i]
            checksum = checksum & 0xFFFF
        return checksum

    def send_message(self, message):
        """Build message to conform to the Broadlink specs and send it"""
        broadcast = message.device.ip in ["255.255.255.255", "224.0.0.251"]
        if broadcast or message.public:
            logging.debug("Brodcasting to {}".format(message.device.ip))
            packet = bytearray(8)
            try:
                message.payload = message.payload + bytearray(40 - len(message.payload))
            except:
                pass  # Most probably more than 40 bytes long payload
            packet = packet + message.payload
        else:
            packet = bytearray(56)
            packet[0] = 0x5A
            packet[1 : 1 + len(message.device.connect_id)] = message.device.connect_id

        packet[36:38] = message.device.dev_id.to_bytes(2, byteorder="little")
        packet[38] = message.cmd

        if not (broadcast or message.public):
            packet[40:42] = message.device.next.to_bytes(2, byteorder="little")
            packet[42:48] = message.device.mactobytes
            packet[48:50] = message.device.dev_id.to_bytes(2, byteorder="little")
            if len(message.payload) % 16:
                message.payload = message.payload + bytearray(
                    16 - len(message.payload) % 16
                )

            checksum = self._checksum(message.payload)
            packet[52:54] = checksum.to_bytes(2, byteorder="little")

            if message.encrypt:
                message.payload = message.device.encrypt(message.payload)

            packet = packet + message.payload

        checksum = self._checksum(packet)
        packet[32:34] = checksum.to_bytes(2, byteorder="little")

        self.waiting[message.device] = (
            message.ret,
            message.cb,
            dt.datetime.now(),
            message.multiple,
        )
        logging.debug("Sending to {}: {}".format(message.device.ip, packet))
        self.transport.sendto(packet, (message.device.ip, 80))

    def cleanup(self):
        """Remove overdue devices from the waiting list"""
        try:
            logging.debug("Clean-up time")

            now = dt.datetime.now()
            for dev in [x for x in self.waiting]:
                c, cb, t, k = self.waiting[dev]
                if (t + dt.timedelta(seconds=TIMEOUT)) < now:
                    del self.waiting[dev]
        except Exception as e:
            logging.debug("Oops while cleaning: {}".format(e))

    async def discovery(self, frequency=700):
        """Convenience corouting to issue discovery message and gnerate ]
        and register new devices. Frequency represent the laps of time (in secs)
        between discoveries """
        try:
            while self.transport is None:
                await aio.sleep(2)
            logging.debug("Starting discovery")
            ip, port = self.transport.get_extra_info("sockname")
            logging.debug("Starting discovery ({}, {})".format(ip, port))
            mydev = BroadlinkDevice(0x1234, "Scout")
            mydev.controller = self
            while True:
                total = frequency
                mydev.hello(ip, port)
                try:
                    while True:
                        newdev = await aio.wait_for(mydev.result.get(), timeout=5.0)
                        self.register(newdev)
                except aio.TimeoutError:
                    logging.debug("Waited in vain")
                    self.cleanup()
                    while total > 0:
                        if self.stop_discovery:
                            frequency = 0
                            break
                        logging.debug("Decreasing")
                        total -= DSTEPS
                        await aio.sleep(DSTEPS)
                except Exception as e:
                    logging.debug("Ooops something went wrong: {}".format(e))
                if frequency == 0:
                    break
        except Exception as e:
            logging.debug("Ooops in discovery: {}".format(e))


def gen_device(dtype, ip, mac, desc, cloud):
    """Convenience function that generates devices based on they type."""

    devices = {
        # sp1: [0],
        sp2: [
            0x2711,  # SP2
            0x2719,
            0x7919,
            0x271A,
            0x791A,  # Honeywell SP2
            0x2720,  # SPMini
            0x753E,  # SP3
            0x7D00,  # OEM branded SP3
            0x947A,
            0x9479,  # SP3S
            0x2728,  # SPMini2
            0x2733,
            0x273E,  # OEM branded SPMini
            0x7530,
            0x7546,
            0x7918,  # OEM branded SPMini2
            0x7D0D,  # TMall OEM SPMini3
            0x2736,  # SPMiniPlus
        ],
        rm: [
            0x2712,  # RM2
            0x2737,  # RM Mini
            0x273D,  # RM Pro Phicomm
            0x2783,  # RM2 Home Plus
            0x277C,  # RM2 Home Plus GDT
            0x278F,  # RM Mini Shate
            0x27C2,  # RM Mini 3
            0x27D1,  # new RM Mini3
            0x27DE,  # RM Mini 3 (C)
        ],
        rm4: [
            0x51DA,  # RM4 Mini
            0x5F36,  # RM Mini 3
            0x6070,  # RM4c Mini
            0x610E,  # RM4 Mini
            0x610F,  # RM4c
            0x62BC,  # RM4 Mini
            0x62BE,  # RM4c
            0x6364,  # RM4S
            0x648D,  # RM4 mini
            0x6539,  # RM4c Mini
            0x653A,  # RM4 mini
        ],
        rmp: [
            0x272A,  # RM2 Pro Plus
            0x2787,  # RM2 Pro Plus2
            0x279D,  # RM2 Pro Plus3
            0x27A9,  # RM2 Pro Plus_300
            0x278B,  # RM2 Pro Plus BL
            0x2797,  # RM2 Pro Plus HYC
            0x27A1,  # RM2 Pro Plus R1
            0x27A6,  # RM2 Pro PP
        ],
        rm4p: [
            0x6026,  # RM4 Pro
            0x61A2,  # RM4 pro
            0x649B,  # RM4 pro
            0x653C,  # RM4 pro
        ],
        a1: [0x2714],  # A1
        mp1: [
            0x4EB5,  # MP1
            0x4EF7,  # Honyar oem mp1
            0x4F1B,  # MP1-1K3S2U
            0x4F65,  # MP1-1K3S2U
        ],
        # hysen: [0x4EAD],  # Hysen controller
        # S1C: [0x2722],  # S1 (SmartOne Alarm Kit)
        # dooya: [0x4E4D]  # Dooya DT360E (DOOYA_CURTAIN_V2)
    }

    # Look for the class associated to devtype in devices
    [device_class] = [dev for dev in devices if dtype in devices[dev]] or [None]
    if device_class is None:
        print("Unknow device type 0x%x" % dtype)
        return BroadlinkDevice(dtype, name=desc, cloud=cloud)
    return device_class(ip=ip, mac=mac, devtype=dtype, name=desc, cloud=cloud)


if __name__ == "__main__":
    import sys

    alock = aio.Lock()

    def myprocess(dev):
        print(
            "Got new device {} {} at {}".format(
                dev.name, "0x%04x" % dev.dev_type, dev.ip
            )
        )
        dev.name = "Office Remote"
        t3 = event_loop.create_task(do_test(dev))

    async def next_phase():
        print("You can stop now")
        print("Get ready to press  the command once>")
        await aio.sleep(5)
        alock.release()
        print("Press the command button once")

    async def do_test(dev):
        await aio.sleep(5)
        logging.debug("Checking Temperature")
        temp = await dev.temperature_check()
        if temp is not None:
            print("Got temperature {}’C".format(temp))
        else:
            print("Could not get the temperature")
        # print("Learning IR")
        # code = await dev.learn_ir_code(timeout=10)
        # if not code:
        # print("Did not learn")
        # return
        # await aio.sleep(5)
        # logging.debug("Echoing data")
        # resu = await dev.send_code(code)
        # if resu:
        # print("Code sent")
        # else:
        # print("Code could not be sent")

        # logging.debug("Learning RF")
        # await alock.acquire()
        # print("\n\nPlease press the command button continuously")
        # code = await dev.learn_rf_code(timeout=10,cb=next_phase, lock=alock)
        # if not code:
        # print("Did not learn")
        # return
        # print("Got code")
        # await aio.sleep(5)
        # logging.debug("Echoing data")
        # resu = await dev.send_code(code)
        # if resu:
        # print("Code sent")
        # else:
        # print("Code could not be sent")

    print("Going for it")
    logging.basicConfig(level=logging.INFO)
    event_loop = aio.get_event_loop()
    blproto = BroadlinkProtocol(process=myprocess)
    coro = event_loop.create_datagram_endpoint(
        lambda: blproto, local_addr=("192.168.77.1", 0)
    )
    task = event_loop.create_task(coro)
    t2 = event_loop.create_task(blproto.discovery())
    event_loop.run_forever()
