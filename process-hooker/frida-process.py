# -*- coding: utf-8 -*-
import frida
import argparse
import os
import time

__author__ = "Sean Wilson  - @seanmw"
__author__ += " Mike Sconzo - @sooshie"
__version__ = "1"

####################################################################################################
# Changelog
#
# 7.10.2020
#  - Tested and cleaned up with Frida 12.10.4
#  - Forked the original project to make it a bit more generic and removed all the cscript specific stuff
#  - Made this script Python3 compatible
#
# 5.30.2017
#  - Tested with Frida 10.0.9
#  - Did some initial testing and added support for wsf files
#
# 5.11.2017
#  - Added hook for application stdout/stderr output. This should give more details when scripts fail or hang
#  - Changed debug var to be passed in via the class constructor vs a function argument
#  - Added debug hook for the device being lost.
#
# 5.7.2017
#  - Cleaned up how the script exits
#  - Added logging for when the script host has terminated or the injected script is destroyed
#
#
######################################################################################################


class processHooker(object):

    def __init__(self, process_sample, debug=False):
        self.device = None
        self.script = None
        self._process_terminated = False
        self._debug = debug
        self.process_sample = process_sample
        

    def on_detach(self, message, data):
        print(' [!] Process has terminated!')
        try:
            print('     |- Process Id: %s' % message.pid)
        except:
            pass
        print('     |- Message: %s' % data)
        self._process_terminated = True
        print(' [!] Exiting...')
        

    def on_destroyed(self):
        print(' [!] Warning: Instrumentation script has been destroyed!')
        

    def on_message(self, message, data):
        if message['type'] == 'send':
            msg_data = message['payload']

            if msg_data['name'] == 'log':
                try:
                    print('%s' % msg_data['payload'])
                    self.script.post({'type': 'ack'})
                except Exception as e:
                    print(e)
            elif msg_data['name'] == 'instr':
                try:
                    hmsg = msg_data['hookdata']
                    if hmsg['hook'] == 'clsid':
                        print(" CLSIDFromProgID Called")
                        print("  |-ProgId: %s" % hmsg['progid'])
                    elif hmsg['hook'] == 'dns':
                        print(" DNS Lookup")
                        print("  |-Host: %s" % hmsg['host'])
                    elif hmsg['hook'] == 'debugger':
                        print(" Debugger Check")
                        print("  |-Returned 0")
                    elif hmsg['hook'] == 'shell':
                        print(" ShellExecute Called")
                        print("  |-nShow: %s " % hmsg['nshow'])
                        print("  |-Command: %s" % hmsg['cmd'])
                        print("  |-Params: %s" % hmsg['params'])
                    elif hmsg['hook'] == 'wsasend':
                        print(" WSASend Called")
                        print("  |-Request Data Start")
                        rdata = hmsg['request'].split('\n')
                        for req in rdata:
                            print("    %s" % req)
                        print("  |-Request Data End")
                    else:
                        print('%s ' % msg_data['hookdata'])
                    print('')
                except TypeError as te:
                    print(' [!] Error parsing hook data!')
                    print(' [!] Error: %s' % te)
        else:
            print(' [!] Error: %s' % message)

    def on_output(self, pid, fd, data):
        if not data:
            return

        lmod = " [!] stderr"

        if fd == 1:
            lmod = " [*] stdout"

        data = data.split('\n')
        for line in data:
            print(' %s> %s' % (lmod, line))

    def on_lost(self):
        if self._debug:
            print(" [*] Device Disconnected.")

    def eval_script(self,
                    enable_shell=False,
                    disable_dns=False,
                    disable_send=False,
                    disable_com=False):

        self.device = frida.get_local_device()
        self.device.on('output', self.on_output)
        self.device.on('lost', self.on_lost)

        # Spawn and attach to the process
        pid = frida.spawn(self.process_sample)
        session = frida.attach(pid)

        # attach to the session
        with open("process_hooker.js") as fp:
            script_js = fp.read()

        self.script = session.create_script(script_js, name="process_hooker.js")

        self.script.on('message', self.on_message)

        session.on('detached', self.on_detach)

        self.script.on('destroyed', self.on_destroyed)

        self.script.load()

        # Set Script variables
        print(' [*] Setting Script Vars...')
        self.script.post({"type": "set_script_vars",
                          "debug": self._debug,
                          "disable_dns": disable_dns,
                          "enable_shell": enable_shell,
                          "disable_send": disable_send,
                          "disable_com": disable_com})

        # Sleep for a second to ensure the vars are set..
        time.sleep(1)

        print(' [*] Hooking Process %s' % pid)
        frida.resume(pid)

        print(' Press ctrl-c to kill the process...')
        # Keep the process running...
        while True:
            try:
                time.sleep(0.5)
                if self._process_terminated:
                    break
            except KeyboardInterrupt:
                break

        if not self._process_terminated:
            # Kill it with fire
            frida.kill(pid)

def main():
    parser = argparse.ArgumentParser(description="frida-wshook.py your friendly WSH Hooker")
    parser.add_argument('--debug', dest='debug', action='store_true', help="Output debug info")
    parser.add_argument('--disable_dns', dest='disable_dns', action='store_true', help="Disable DNS Requests")
    parser.add_argument('--disable_com_init', dest='disable_com_init', action='store_true', help="Disable COM Object Id Lookup")
    parser.add_argument('--enable_shell', dest='enable_shell', action='store_true', help="Enable Shell Commands")
    parser.add_argument('--disable_net', dest='disable_net', action='store_true', help="Disable Network Requests")
    parser.add_argument('processSample', nargs=1, help='File path of the process sample you want to analyze')

    args = parser.parse_args()

    processhooker = processHooker(args.processSample, debug=args.debug)

    # Evaluate Script file...
    processhooker.eval_script(args.enable_shell,
                           args.disable_dns,
                           args.disable_net,
                           args.disable_com_init)

if __name__ == '__main__':
    main()