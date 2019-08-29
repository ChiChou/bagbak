#!/usr/bin/env python
# encoding: utf-8

from __future__ import print_function

import codecs
import sys
import tempfile
import os
import shutil
import time
from collections import namedtuple

import frida


def fatal(reason):
    print(reason)
    sys.exit(-1)


def find_app(app_name_or_id, device_id, device_ip):
    if device_id is None:
        if device_ip is None:
            dev = frida.get_usb_device()
        else:
            frida.get_device_manager().add_remote_device(device_ip)
            dev = frida.get_device("tcp@" + device_ip)
    else:
        try:
            dev = next(dev for dev in frida.enumerate_devices()
                       if dev.id.startswith(device_id))
        except StopIteration:
            fatal('device id %s not found' % device_id)

    if dev.type not in ('tether', 'remote', 'usb'):
        fatal('unable to find device')

    try:
        app = next(app for app in dev.enumerate_applications() if
                   app_name_or_id == app.identifier or
                   app_name_or_id == app.name)
    except:
        print('app "%s" not found' % app_name_or_id)
        print('installed app:')
        for app in dev.enumerate_applications():
            print('%s (%s)' % (app.name, app.identifier))
        fatal('')

    return dev, app


class FileReceiver(object):
    def __init__(self, script, filename):
        self.script = script
        self.session = None
        self.filename = filename
        self.fp = None
        self.size = 0

    def connect(self):
        self.script.on('message', self.on_message)

    def on_message(self, msg, data):
        if msg.get('type') != 'send':
            print('unknown message:', msg)
            return

        payload = msg.get('payload', {})
        subject = payload.get('subject')
        if subject == 'download':
            method_mapping = {
                'start': self.on_download_start,
                'data': self.on_download_data,
                'end': self.on_download_finish,
                'error': self.on_download_error,
            }
            method = method_mapping[payload.get('event')]
            method(data=data, **payload)
        elif subject == 'finish':
            print('bye')
            self.session.detach()
            self.device.kill(self.app.pid)
            sys.exit(0)
        else:
            print('unknown message')
            print(msg)

    def on_download_start(self, session, size, **kwargs):
        self.session = session
        self.size = size
        self.fp = open(self.filename, 'wb')

    def on_download_data(self, session, data, **kwargs):
        assert(self.session == session)
        self.fp.write(data)
        self.script.post({'type': 'flush', 'payload': {}})

    def on_download_finish(self, session, **kwargs):
        self.close_session(session)

    def on_download_error(self, session, **kwargs):
        self.close_session(session)

    def close_session(self, session):
        self.fp.close()
        self.session = None

def on_console(level, text):
    print('[%s] %s' % (level, text))

class IPADump(object):

    def __init__(self, device, app, output=None, verbose=False, keep_watch=False, skip_plugins=False):
        self.device = device
        self.app = app
        self.session = None
        self.cwd = None
        self.tasks = {}
        self.output = output
        self.verbose = verbose
        self.skip_plugins = skip_plugins
        self.opt = {
            'keepWatch': keep_watch,
            'verbose': verbose,
        }
        self.ipa_name = ''

    def on_detach(self, reason):
        if reason != 'application-requested':
            print('[fatal] session detached, reason:', reason)
            sys.exit(-1)

    def dump(self):
        on_console('info', 'attaching to target')
        pid = self.app.pid
        spawn = not bool(pid)
        front = self.device.get_frontmost_application()
        if pid and front and front.pid != pid:
            self.device.kill(pid)
            spawn = True

        if spawn:
            pid = self.device.spawn(self.app.identifier)
            time.sleep(1)
            session = self.device.attach(pid)
            self.device.resume(pid)
        else:
            session = self.device.attach(pid)

        session.on('detached', self.on_detach)
        session.enable_jit()
        script = session.create_script(self.agent_source)
        script.set_log_handler(on_console)
        FileReceiver(script, self.ipa_name).connect()
        script.load()

        self.plugins = script.exports.plugins()
        self.script = script
        self.root = self.script.exports.root()

        if len(self.plugins) and self.skip_plugins == False:
            self.dump_with_plugins()
        else:
            decrypted = script.exports.decrypt(self.root)
            self.script.exports.archive(self.root, decrypted, self.opt)

        session.detach()
        # todo: option
        self.device.kill(self.app.pid)

    def dump_with_plugins(self):
        # handle plugins
        self.script.exports.start_pkd()
        pkd = self.device.attach('pkd')
        pkd_script = pkd.create_script(self.agent_source)
        pkd_script.set_log_handler(on_console)
        pkd_script.load()
        pkd_script.exports.skip_pkd_validation_for(self.app.pid)

        decrypted = self.script.exports.decrypt(self.root)
        for identifier in self.plugins:
            pid = self.script.exports.launch(identifier)
            print('plugin %s, pid=%d' % (identifier, pid))
            session = self.device.attach(pid)
            script = session.create_script(self.agent_source)
            script.set_log_handler(on_console)
            script.load()

            decrypted += script.exports.decrypt(self.root)
            session.detach()
            self.device.kill(pid)

        pkd.detach()

        self.fetch_with_new_process(decrypted)

    def fetch_with_new_process(self, decrypted):
        pid = self.device.spawn('/bin/ps')
        time.sleep(1)
        sh = self.device.attach(pid)
        script = sh.create_script(self.agent_source)
        script.set_log_handler(on_console)
        handler = FileReceiver(script, self.ipa_name)
        handler.connect()
        script.load()
        script.exports.archive(self.root, decrypted, self.opt)
        sh.detach()
        self.device.kill(pid)


    def load_agent(self):
        agent = os.path.join('agent', 'dist.js')
        with codecs.open(agent, 'r', 'utf-8') as fp:
            self.agent_source = fp.read()

    def run(self):
        self.load_agent()
        if self.output is None:
            ipa_name = '.'.join([self.app.name, 'ipa'])
        elif os.path.isdir(self.output):
            ipa_name = os.path.join(self.output, '%s.%s' %
                                    (self.app.name, 'ipa'))
        else:
            ipa_name = self.output

        self.ipa_name = ipa_name
        self.dump()
        print('Output: %s' % ipa_name)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', nargs='?', help='device id (prefix)')
    parser.add_argument('--ip', nargs='?', help='ip to connect over network')
    parser.add_argument('app', help='application name or bundle id')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
    parser.add_argument('--keep-watch', action='store_true',
                        default=False, help='preserve WatchOS app'),
    parser.add_argument('--skip-plugins', action='store_true',
                        default=False, help='skip app plugins')
    args = parser.parse_args()

    dev, app = find_app(args.app, args.device, args.ip)

    task = IPADump(dev, app,
                   keep_watch=args.keep_watch,
                   output=args.output,
                   verbose=args.verbose,
                   skip_plugins=args.skip_plugins)
    task.run()


if __name__ == '__main__':
    main()
