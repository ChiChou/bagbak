#!/usr/bin/env python3
# encoding: utf-8

import codecs
import sys
import tempfile
import os
import shutil
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
            'progress': {},
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
        elif subject == 'decryption' and payload.get('event') == 'progress':
            print('progress')
            self.opt['progress'] = msg.get('progress')
        elif subject == 'finish':
            print('bye')
            self.session.detach()
            sys.exit(0)
        elif subject == 'mkdir':
            self.on_mkdir(**payload)
        else:
            print('unknown message')
            print(msg)

    def dump(self):
        def on_console(level, text):
            print('[%s]' % level, text)

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

        script = session.create_script(self.agent_source)
        script.set_log_handler(on_console)
        script.on('message', self.on_message)
        script.load()

        # todo: refactor me
        self.plugins = script.exports.plugins()
        self.script = script
        if len(self.plugins):
            self.dump_with_plugins()
        else:
            script.export.dump(self.opt)

        session.detach()

    def dump_with_plugins(self):
        # handle plugins
        pkd = self.device.attach('pkd')
        pkd_script = pkd.create_script(self.agent_source)
        pkd_script.load()
        pkd_script.exports.skip_pkd_validation_for(self.app.pid)

        Plugin = namedtuple('Plugin', ['id', 'session', 'pid', 'script'])
        spawned = set()
        all_groups = []
        for identifier in self.plugins:
            pid = self.script.exports.launch(identifier)
            print('plugin %s, pid=%d' % (identifier, pid))
            session = self.device.attach(pid)
            script = session.create_script(self.agent_source)
            script.load()

            plugin = Plugin(id=identifier, session=session, pid=pid, script=script)
            spawned.add(plugin)
            all_groups.append(set(script.exports.groups()))

        pkd.detach()
        group = set.intersection(*all_groups).pop()
        if not group:
            raise RuntimeError('''App includes extension, but no valid '''
                               '''app group found. Please file a bug to Github''')

        root = self.script.exports.root()
        container = self.script.exports.path_for_group(group)
        print('group:', group)
        print('container:', container)
        print('root:', root)
        self.opt['dest'] = container

        decrypted = self.script.exports.decrypt(root, container)
        for plugin in spawned:
            decrypted += plugin.script.exports.decrypt(root, container)
            plugin.session.detach()
            self.device.kill(plugin.pid)
        
        self.script.exports.archive(root, container, decrypted, self.opt)

    def load_agent(self):
        agent = os.path.join('agent', 'dist.js')
        with codecs.open(agent, 'r', 'utf-8') as fp:
            self.agent_source = fp.read()

    def run(self):
        self.load_agent()
        with tempfile.TemporaryDirectory() as tempdir:
            self.cwd = os.path.join(tempdir, 'Payload')
            os.mkdir(self.cwd)
            self.dump()
            if self.verbose:
                print('File transfer finished, packaging')
            zip_name = shutil.make_archive(self.app.name, 'zip', tempdir)

        if self.output is None:
            ipa_name = '.'.join([self.app.name, 'ipa'])
        elif os.path.isdir(self.output):
            ipa_name = os.path.join(self.output, '%s.%s' %
                                    (self.app.name, 'ipa'))
        else:
            ipa_name = self.output

        os.rename(zip_name, ipa_name)
        print('Output: %s' % ipa_name)


def main():
    import sys
    if sys.version_info.major < 3:
        fatal('this tool requires python 3 or higher, detected:\n%s' % sys.version)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', nargs='?', help='device id (prefix)')
    parser.add_argument('--ip', nargs='?', help='ip to connect over network')
    parser.add_argument('app', help='application name or bundle id')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument('-v', '--verbose', help='verbose mode')
    parser.add_argument('--keep-watch', action='store_true',
                        default=False, help='preserve WatchOS app')
    args = parser.parse_args()

    dev, app = find_app(args.app, args.device, args.ip)

    task = IPADump(dev, app,
                   keep_watch=args.keep_watch,
                   output=args.output,
                   verbose=args.verbose)
    task.run()


if __name__ == '__main__':
    main()
