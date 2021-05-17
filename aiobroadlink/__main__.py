#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is an example on how to use aiolifx
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
import sys
import asyncio as aio
import aiobroadlink as abl
import argparse, random, json, os, logging, base64

devicelist = {}
selected = None
alock = None
event_loop = None


def getname(dev):
    return dev.dev + "-" + "".join(random.choices("abcdefghijklmn0pqrstuvwxyz", k=6))


# Simple devices control from console
def Process(dev):
    global devicelist
    print("Got new device {}".format(dev.dev))
    newname = getname(dev)
    devicelist[newname] = dev


def A1menu():
    print("\t[1]\tCheck Sensor")
    print("")
    print("\t[3]\tRename (New name)")


async def A1process(dev, vals):
    global devicelist

    if int(vals[0]) == 1:
        vals = await dev.sensor_check()
        if not vals:
            print("Something went wrong")
        else:
            for x, y in vals.items():
                print("{}:\t{}".format(x.capitalize(), y))
    elif int(vals[0]) == 3:
        # rename
        found = False
        for k, d in devicelist.values():
            if d == dev:
                found = True
                break
        if found:
            if " ".join(vals[1:]) in devicelist:
                print("Warning: Name already exists. Overwritting.")

            else:
                del devicelist[k]
        devicelist[" ".join(vals[1:])] = dev
    else:
        print("Unknown command")
    await aio.sleep(0)


def RMmenu():
    print("\t[1]\tCheck Sensor")
    print("\t[2]\tSend Command (device name) (command name)")
    print("\t[3]\tLearn IR Command (device name) (command name)")
    print("")
    print("\t[6]\tRename (New name)")


def RMpromenu():
    print("\t[1]\tCheck Sensor")
    print("\t[2]\tSend Command (device name) (command name)")
    print("\t[3]\tLearn IR Command (device name) (command name)")
    print("\t[4]\tLearn RF Command (device name) (command name)")
    print("")
    print("\t[7]\tRename (New name)")


async def RMprocess(dev, vals):
    global learnt_cmd, opts, devicelist, alock
    if int(vals[0]) == 1:
        tmp = await dev.temperature_check()
        print("Temperature is {}°Ċ".format(tmp))
        if getattr(dev, "humidity_check", None):
            tmp = await dev.humidity_check()
            print("Humidity is {}%".format(tmp))

    elif int(vals[0]) == 2:
        if len(vals) > 3:
            print(
                "Warning: Neither the device name nor the command name can contain space. Will try anyway."
            )
        if len(vals) < 3:
            print(
                "Error: To send a code you must specify a device name and a command name."
            )
        elif vals[1] not in learnt_cmd:
            print("Device {} is not known.".format(vals[1]))
            print("Known devices are {}".format(learnt_cmd.keys()))
        else:
            if vals[2] not in learnt_cmd[vals[1]]:
                print("Device {} has no {} command.".format(vals[1], vals[2]))
                print("Known commands are {}".format(learnt_cmd[vals[1]].keys()))
            else:
                if not await dev.send_code(
                    base64.b64decode(learnt_cmd[vals[1]][vals[2]])
                ):
                    print("Error: Code could not be sent")

    elif int(vals[0]) == 3:
        if len(vals) != 3:
            print("Error: You must specify single worded device name and command name.")
        else:
            print(
                "Learning IR. Please press the command to learn on the remote control."
            )
            code = await dev.learn_ir_code(timeout=10)
            if not code:
                print("Could not learn command")
            else:
                if vals[1] not in learnt_cmd:
                    learnt_cmd[vals[1]] = {}
                if vals[2] not in learnt_cmd[vals[1]]:
                    learnt_cmd[vals[1]][vals[2]] = {}
                learnt_cmd[vals[1]][vals[2]] = base64.b64encode(code).decode("ascii")
                with open(opts.learnt, "w") as f:
                    json.dump(learnt_cmd, f)
                print(
                    "Command {} for device {} has been learnt".format(vals[2], vals[1])
                )
    elif int(vals[0]) == 4:

        if not isinstance(dev, abl.rmp):
            print("Unknown command")
        else:

            async def next_phase():
                print("You can stop now")
                print("You will now press the command to learn once.")
                print("Hit <Return> when ready.")
                await aio.sleep(0)

            if len(vals) != 3:
                print(
                    "Error: You must specify single worded device name and command name."
                )
            else:
                alock = aio.Lock()
                await alock.acquire()
                print(
                    "Learning RF. Please continuously press the command to learn on the remote control."
                )
                print("This is so that the device will lock onto the frequency.")
                print("Hit <Return> when ready.")
                await alock.acquire()
                code = await dev.learn_rf_code(timeout=10, cb=next_phase, lock=alock)

                alock = None
                if not code:
                    print("Could not learn command")
                else:
                    if vals[1] not in learnt_cmd:
                        learnt_cmd[vals[1]] = {}
                    if vals[2] not in learnt_cmd[vals[1]]:
                        learnt_cmd[vals[1]][vals[2]] = {}
                    learnt_cmd[vals[1]][vals[2]] = base64.b64encode(code).decode(
                        "ascii"
                    )
                    with open(opts.learnt, "w") as f:
                        json.dump(learnt_cmd, f)
                    print(
                        "Command {} for device {} has been learnt".format(
                            vals[2], vals[1]
                        )
                    )

    elif int(vals[0]) == 6:
        # rename
        found = False
        for k, d in devicelist.items():
            if d == dev:
                found = True
                break
        if found:
            if " ".join(vals[1:]) in devicelist:
                print("Warning: Name already exists. Overwritting.")

            else:
                del devicelist[k]
        devicelist[" ".join(vals[1:])] = dev
    else:
        print("Unknown command")
    await aio.sleep(0)


def MP1menu():
    print("\t[1]\tCheck Power [outlet id (1 t0 4)]")
    print("\t[2]\tSet Power <outlet id> <state>")
    print("")
    print("\t[4]\tRename (New name)")


async def MP1process(dev, vals):

    if int(vals[0]) == 1:
        if len(vals) > 1:
            pwr = await dev.power_check(int(vals[1]) - 1)
            print("Socket {} is {}".format(vals[1], pwr))
        else:
            pwrl = await dev.power_check()
            idx = 1
            for x in pwrl:
                print("Socket {} is {}".format(idx, x))
    elif int(vals[0]) == 2:
        if len(vals) < 3:
            print("Error: You must specify a socket id and a state")
        else:
            try:
                msg = "Error: Socket id must be a number."
                socket = int(vals[1])
                if vals[2].lower() not in ["on", "off", "1", "0"]:
                    msg = "Error: State must be one of 0, 1, on, off."
                    raise Exception

                pwr = await dev.power_set(
                    int(vals[1]), "on" if vals[2].lower() in ["on", "1"] else "off"
                )
                if pwr:
                    print("Power was set on socket {}".format(vals[1]))
                else:
                    print("Error: Power could not be set on socket {}".format(vals[1]))
            except:
                print(msg)

    elif int(vals[0]) == 4:
        # rename
        found = False
        for k, d in devicelist.items():
            if d == dev:
                found = True
                break
        if found:
            if " ".join(vals[1:]) in devicelist:
                print("Warning: Name already exists. Overwritting.")

            else:
                del devicelist[k]
        devicelist[" ".join(vals[1:])] = dev
    else:
        print("Unknown command")
    await aio.sleep(0)


async def do_provision(ssid, passphrase, security):
    global devicelist
    dev = abl.BroadlinkDevice(0)
    dev.mac = "aa:bb:cc:dd:ee:ff"
    blproto.register(dev)
    resu = await dev.provision(ssid, passphrase, security)
    print("Let's hope the device was provisioned")
    blproto.unregister(dev)
    dname = None
    for aname in devicelist:
        if devicelist[aname] == dev:
            dname = aname
            break
    if dname:
        del devicelist[dname]


def readin():
    """Reading from stdin and displaying menu"""
    global devicelist, selected, alock, event_loop

    lonames = [x for x in devicelist.keys()]
    lonames.sort()

    selection = sys.stdin.readline().strip("\n")
    logging.debug("Checking lock {}".format(alock))
    if alock:
        logging.debug("Releasing")
        try:
            alock.release()
        except:
            pass
        return

    lov = [x for x in selection.split(" ") if x != ""]
    if lov:
        if selected:
            # try:
            if True:
                if int(lov[0]) == 0:
                    pass
                elif selected.dev == "A1":
                    t3 = event_loop.create_task(A1process(selected, lov))
                elif selected.dev == "RM":
                    t3 = event_loop.create_task(RMprocess(selected, lov))
                elif selected.dev == "RM4":
                    t3 = event_loop.create_task(RMprocess(selected, lov))
                elif selected.dev == "RM PRO":
                    t3 = event_loop.create_task(RMprocess(selected, lov))
                elif selected.dev == "RM4 PRO":
                    t3 = event_loop.create_task(RMprocess(selected, lov))
                elif selected.dev == "MP1":
                    t3 = event_loop.create_task(MP1process(selected, lov))
                elif selected.dev == "SP2":
                    t3 = event_loop.create_task(SP2process(selected, lov))
                # except:
                # print ("\nError: Selection must be a number.\n")
                selected = None
        else:
            try:
                if int(lov[0]) > 0:
                    if int(lov[0]) <= len(devicelist):
                        selected = devicelist[lonames[int(lov[0]) - 1]]
                    elif int(lov[0]) == 99:
                        # Provision
                        if len(lov) < 4:
                            print(
                                "Error: You must specify a security mode, a SSID and a passphrase"
                            )
                        elif lov[1].lower() not in [
                            "none",
                            "wep",
                            "wpa1",
                            "wpa2",
                            "wpa1/2",
                        ]:
                            print(
                                "Error: Security mode must be one of: none, wep, wpa1, wpa2 or wpa1/2"
                            )
                        else:
                            t3 = event_loop.create_task(
                                do_provision(lov[2], " ".join(lov[3:]), lov[1].lower())
                            )
                            if resu:
                                print("Device was provisioned")
                            else:
                                print("Error: Device could not be provisioned")
                    else:
                        print("\nError: Not a valid selection.\n")

            except:
                print("\nError: Selection must be a number.\n")

    if selected:
        for x in devicelist:
            if devicelist[x] == selected:
                name = x
                break

        print("Select Function for {}:".format(name))
        if selected.dev == "A1":
            A1menu()
        elif selected.dev == "RM":
            RMmenu()
        elif selected.dev == "RM4":
            RMmenu()
        elif selected.dev == "RM PRO":
            RMpromenu()
        elif selected.dev == "RM4 PRO":
            RMpromenu()
        elif selected.dev == "MP1":
            MP1menu()
        elif selected.dev == "SP2":
            SP2menu()
        print("")
        print("\t[0]\tBack to device selection")
    else:
        idx = 1
        print("Select Device:")
        lonames = [x for x in devicelist.keys()]
        lonames.sort()
        for x in lonames:
            print("\t[{}]\t{}".format(idx, x))
            idx += 1

        print("\n\t[99]\tProvision security SSID Passphrase")
    print("")
    print("Your choice: ", end="", flush=True)


def main(args=None):
    global learnt_cmd
    global event_loop
    global opts

    parser = argparse.ArgumentParser(
        description="Track and interact with Broadlink devices."
    )
    parser.add_argument("-i", "--ip", default="", help="IP address to bind to.")
    parser.add_argument(
        "-l",
        "--learnt",
        default="~/.aiobroadlink",
        help="Json file used to keep learnt commands for RM2 devices.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="Print unexpected messages.",
    )
    try:
        opts = parser.parse_args()
    except Exception as e:
        parser.error("Error: " + str(e))

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    learnt_cmd = {}
    opts.learnt = os.path.abspath(os.path.expanduser(opts.learnt))
    if not os.path.isfile(opts.learnt):
        with open(opts.learnt, "w") as f:
            json.dump({}, f)
    else:
        with open(opts.learnt, "r+") as f:
            learnt_cmd = json.load(f)

    if not opts.ip:
        # Let's try to figure it out"
        try:
            import netifaces

            for iface in netifaces.interfaces():
                alladdr = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in alladdr:
                    alladdr = alladdr[netifaces.AF_INET]
                    for addr in alladdr:
                        if not addr["addr"].startswith("127."):
                            logging.debug(
                                "Selecting address {} on {}".format(addr["addr"], iface)
                            )
                            opts.ip = addr["addr"]
                            break
                    if opts.ip:
                        break
            if not opts.ip:
                raise Exception
        except:
            print(
                "No IP address was specified. We tried but could not guess it. Make sure netifaces is installed"
            )
            sys.exit(1)

    event_loop = aio.get_event_loop()
    try:
        blproto = abl.BroadlinkProtocol(process=Process)
        coro = event_loop.create_datagram_endpoint(
            lambda: blproto, local_addr=(opts.ip, 0)
        )
        task = event_loop.create_task(coro)
        event_loop.add_reader(sys.stdin, readin)
        t2 = event_loop.create_task(blproto.discovery())
        print('Hit "Enter" to start')
        print("Use Ctrl-C to quit")
        event_loop.run_forever()
    except KeyboardInterrupt:
        print("\nExiting at user request.")
    except Exception as e:
        print("\nExiting because {}.".format(e))
        pass
    finally:
        blproto.stop_discovery = True
        event_loop.remove_reader(sys.stdin)
        event_loop.run_until_complete(aio.sleep(10))
        event_loop.close()


if __name__ == "__main__":
    main()
