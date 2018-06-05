#!/usr/bin/env python3
# encoding: utf-8

import codecs
import sys
import tempfile
import os
import shutil
import threading

import frida


def fatal(reason):
    print(reason)
    sys.exit(-1)


def find_app(app_name_or_id, device_id, device_ip):
    if device_id is None:
        if device_ip is None:
            dev = frida.get_usb_device()
        else:
            dManager = frida.get_device_manager()
            changed = threading.Event()
            frida.get_device_manager().add_remote_device(device_ip)

            def on_changed():
                changed.set()

            dManager.on('changed', on_changed)
            dev = frida.get_device("tcp@" + device_ip)
    else:
        try:
            dev = next(dev for dev in frida.enumerate_devices()
                       if dev.id.startswith(device_id))
        except StopIteration:
            fatal('device id %s not found' % device_id)

    if not (dev.type == 'tether' or dev.type == 'remote'):
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


class Task(object):

    def __init__(self, session, path, info):
        self.session = session
        self.path = path
        self.info = info
        self.file = open(self.path, 'wb')

    def write(self, data):
        self.file.write(data)

    def finish(self):
        self.close()
        time_pair = tuple(self.info.get(key)
                          for key in ('creation', 'modification'))
        try:
            if all(time_pair):
                os.utime(self.path, time_pair)
            os.chmod(self.path, self.info['permission'])
        except FileNotFoundError:
            pass

    def close(self):
        self.file.close()


class IPADump(object):

    def __init__(self, device, app, output=None, verbose=False, keep_watch=False):
        self.device = device
        self.app = app
        self.session = None
        self.cwd = None
        self.tasks = {}
        self.output = output
        self.verbose = verbose
        self.opt = {
            'keepWatch': keep_watch,
        }

    def on_download_start(self, session, relative, info, **kwargs):
        if self.verbose:
            print('downloading', relative)
        local_path = self.local_path(relative)
        self.tasks[session] = Task(session, local_path, info)

    def on_download_data(self, session, data, **kwargs):
        self.tasks[session].write(data)

    def on_download_finish(self, session, **kwargs):
        self.close_session(session)

    def on_download_error(self, session, **kwargs):
        self.close_session(session)

    def close_session(self, session):
        self.tasks[session].finish()
        del self.tasks[session]

    def local_path(self, relative):
        local_path = os.path.join(self.cwd, relative)
        if not local_path.startswith(self.cwd):
            raise ValueError('path "%s" is illegal' % relative)
        return local_path

    def on_mkdir(self, path, **kwargs):
        local_path = self.local_path(path)
        os.mkdir(local_path)
        return local_path

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
            sys.exit(0)
        elif subject == 'mkdir':
            self.on_mkdir(**payload)
        else:
            print('unknown message')
            print(msg)

    def inject(self):
        def on_console(level, text):
            print('[%s]' % level, text)

        agent = os.path.join('agent', 'dist.js')
        with codecs.open(agent, 'r', 'utf-8') as fp:
            source = fp.read()
        on_console('info', 'attaching to target')
        pid = self.app.pid
        spawn = not bool(pid)
        front = self.device.get_frontmost_application()
        if pid and front and front.pid != pid:
            self.device.kill(pid)
            spawn = True

        if spawn:
            pid = self.device.spawn(self.app.identifier)
            session = self.device.attach(pid)
            self.device.resume(pid)
        else:
            session = self.device.attach(pid)

        script = session.create_script(source)
        script.set_log_handler(on_console)
        script.on('message', self.on_message)
        script.load()
        script.exports.dump(self.opt)
        return session

    def run(self):
        with tempfile.TemporaryDirectory() as tempdir:
            self.cwd = os.path.join(tempdir, 'Payload')
            os.mkdir(self.cwd)
            session = self.inject()
            session.detach()
            if self.verbose:
                print('File transfer finished, packaging')
            zip_name = shutil.make_archive(self.app.name, 'zip', tempdir)

        if self.output is None:
            ipa_name = '.'.join([self.app.name, 'ipa'])
        elif os.path.isdir(self.output):
            ipa_name = os.path.join(self.output, '%s.%s' % (self.app.name, 'ipa'))
        else:
            ipa_name = self.output

        os.rename(zip_name, ipa_name)
        print('Output: %s' % ipa_name)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', nargs='?', help='device id (prefix)')
    parser.add_argument('--ip', nargs='?', help='ip to connect over network')
    parser.add_argument('app', help='application name or bundle id')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument('-v', '--verbose', help='verbose mode')
    parser.add_argument('--keep-watch', action='store_true', default=False, help='preserve WatchOS app')
    args = parser.parse_args()

    dev, app = find_app(args.app, args.device, args.ip)

    task = IPADump(dev, app,
        keep_watch=args.keep_watch,
        output=args.output,
        verbose=args.verbose)
    task.run()

if __name__ == '__main__':
    main()
