#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import mechanize
import cookielib
import getpass
import sys
import os
import zipfile
import urllib
import socket
import ssl
import errno
import argparse
import atexit
import signal
import ConfigParser
import time
import binascii
import hmac
import hashlib

def mkdir_p(path):
    try:
        os.mkdir(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise
"""
OATH code from https://github.com/bdauvergne/python-oath
Copyright 2010, Benjamin Dauvergne

* All rights reserved.
* Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.'''
"""

def truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset+1] & 0xff) << 16 | \
            (bytes[offset+2] & 0xff) << 8 | (bytes[offset+3] & 0xff)
    return v

def dec(h,p):
    v = truncated_value(h)
    v = v % (10**p)
    return '%0*d' % (p, v)

def int2beint64(i):
    hex_counter = hex(long(i))[2:-1]
    hex_counter = '0' * (16 - len(hex_counter)) + hex_counter
    bin_counter = binascii.unhexlify(hex_counter)
    return bin_counter

def hotp(key):
    key = binascii.unhexlify(key)
    counter = int2beint64(int(time.time()) / 30)
    return dec(hmac.new(key, counter, hashlib.sha256).digest(), 6)

class juniper_vpn_wrapper(object):
    def __init__(self, vpn_host, username, password, oath, socks_port):
        self.vpn_host = vpn_host
        self.username = username
        self.password = password
        self.oath = oath
        self.fixed_password = password is not None
        self.socks_port = socks_port

        self.br = mechanize.Browser()

        self.cj = cookielib.LWPCookieJar()
        self.br.set_cookiejar(self.cj)

        # Browser options
        self.br.set_handle_equiv(True)
        self.br.set_handle_redirect(True)
        self.br.set_handle_referer(True)
        self.br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        self.br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                              max_time=1)

        # Want debugging messages?
        #self.br.set_debug_http(True)
        #self.br.set_debug_redirects(True)
        #self.br.set_debug_responses(True)

        self.user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
        self.br.addheaders = [('User-agent', self.user_agent)]

        self.last_action = None
        self.tncc_process = None
        self.needs_2factor = False
        self.key = None

        self.tncc_jar = None
        self.ncsvc_bin = None

    def find_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    def next_action(self):
        if self.find_cookie('DSID'):
            return 'ncsvc'

        for form in self.br.forms():
            if form.name == 'frmLogin':
                return 'login'
            elif form.name == 'frmDefender':
                return 'key'
            elif form.name == 'frmConfirmation':
                return 'continue'
            else:
                raise Exception('Unknown form type:', form.name)
        return 'tncc'

    def run(self):
        # Open landing page
        self.r = self.br.open('https://' + self.vpn_host)
        while True:
            action = self.next_action()
            if action == 'tncc':
                self.action_tncc()
            elif action == 'login':
                self.action_login()
            elif action == 'key':
                self.action_key()
            elif action == 'continue':
                self.action_continue()
            elif action == 'ncsvc':
                self.action_ncsvc()

            self.last_action = action

    def action_tncc(self):
        # Run tncc host checker
        dspreauth_cookie = self.find_cookie('DSPREAUTH')
        if dspreauth_cookie is None:
            raise Exception('Could not find DSPREAUTH key for host checker')

        dssignin_cookie = self.find_cookie('DSSIGNIN')
        dssignin = (dssignin_cookie.value if dssignin_cookie else 'null')

        if not self.tncc_process:
            self.tncc_start()

        args = [('IC', self.vpn_host), ('Cookie', dspreauth_cookie.value), ('DSSIGNIN', dssignin)]

        try:
            self.tncc_send('start', args)
            results = self.tncc_recv()
        except:
            self.tncc_start()
            self.tncc_send('start', args)
            results = self.tncc_recv()

        if len(results) < 4:
            raise Exception('tncc returned insufficent results', results)

        if results[0] == '200':
            dspreauth_cookie.value = results[2]
            self.cj.set_cookie(dspreauth_cookie)
        elif self.last_action == 'tncc':
            raise Exception('tncc returned non 200 code (' + result[0] + ')')
        else:
            self.cj.clear(self.vpn_host, '/dana-na/', 'DSPREAUTH')

        self.r = self.br.open(self.r.geturl())

    def action_login(self):
        # The token used for two-factor is selected when this form is submitted.
        # If we aren't getting a password, then get the key now, otherwise
        # we could be sitting on the two factor key prompt later on waiting
        # on the user.

        if self.password is None or self.last_action == 'login':
            if self.fixed_password:
                print 'Login failed (Invalid username or password?)'
                sys.exit(1)
            else:
                self.password = getpass.getpass('Password:')
                self.needs_2factor = False

        if self.needs_2factor:
            if self.oath:
                self.key = hotp(self.oath)
            else:
                self.key = getpass.getpass('Two-factor key:')
        else:
            self.key = None

        # Enter username/password
        self.br.select_form(nr=0)
        self.br.form['username'] = self.username
        self.br.form['password'] = self.password
        # Untested, a list of availables realms is provided when this
        # is necessary.
        # self.br.form['realm'] = [realm]
        self.r = self.br.submit()

    def action_key(self):
        # Enter key
        self.needs_2factor = True
        if self.oath:
            if self.last_action == 'key':
                print 'Login failed (Invalid OATH key)'
                sys.exit(1)
            self.key = hotp(self.oath)
        elif self.key is None:
            self.key = getpass.getpass('Two-factor key:')
        self.br.select_form(nr=0)
        self.br.form['password'] = self.key
        self.key = None
        self.r = self.br.submit()

    def action_continue(self):
        # Yes, I want to terminate the existing connection
        self.br.select_form(nr=0)
        self.r = self.br.submit()

    def action_ncsvc(self):
        dspreauth_cookie = self.find_cookie('DSPREAUTH')
        if dspreauth_cookie is not None:
            try:
                self.tncc_send('setcookie', [('Cookie', dspreauth_cookie.value)])
            except:
                # TNCC died, bummer
                self.tncc_stop()
        if self.ncsvc_start() == 3:
            # Code 3 indicates that the DSID we tried was invalid
            self.cj.clear(self.vpn_host, '/', 'DSID')
            self.r = self.br.open(self.r.geturl())

    def tncc_send(self, cmd, params):
        v = cmd + '\n'
        for key, val in params:
            v = v + key + '=' + val + '\n'
        self.tncc_socket.send(v)

    def tncc_recv(self):
        ret = self.tncc_socket.recv(1024)
        return ret.splitlines()

    def tncc_init(self):
        class_names = ('net.juniper.tnc.NARPlatform.linux.LinuxHttpNAR',
                       'net.juniper.tnc.HttpNAR.HttpNAR')
        self.class_name = None

        self.tncc_jar = os.path.expanduser('~/.juniper_networks/tncc.jar')
        try:
            if zipfile.ZipFile(self.tncc_jar, 'r').testzip() is not None:
                raise Exception()
        except:
            print 'Downloading tncc.jar...'
            mkdir_p(os.path.expanduser('~/.juniper_networks'))
            urllib.urlretrieve('https://' + self.vpn_host
                               + '/dana-cached/hc/tncc.jar', self.tncc_jar)

        with zipfile.ZipFile(self.tncc_jar, 'r') as jar:
            for name in class_names:
                try:
                    jar.getinfo(name.replace('.', '/') + '.class')
                    self.class_name = name
                    break
                except:
                    pass

        if self.class_name is None:
            raise Exception('Could not find class name for', self.tncc_jar)

        self.tncc_preload = \
            os.path.expanduser('~/.juniper_networks/tncc_preload.so')
        if not os.path.isfile(self.tncc_preload):
            raise Exception('Missing', self.tncc_preload)

    def tncc_stop(self):
        if self.tncc_process is not None:
            try:
                self.tncc_process.terminate()
            except:
                pass
            self.tncc_socket = None
            self.tncc_process.wait()

    def tncc_start(self):
        # tncc is the host checker app. It can check different
        # security policies of the host and report back. We have
        # to send it a preauth key (from the DSPREAUTH cookie)
        # and it sends back a new cookie value we submit.
        # After logging in, we send back another cookie to tncc.
        # Subsequently, it contacts https://<vpn_host:443 every
        # 10 minutes.

        if not self.tncc_jar:
            self.tncc_init()

        self.tncc_socket, sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        null = open(os.devnull, 'w')

        self.tncc_process = subprocess.Popen(['java',
            '-classpath', self.tncc_jar, self.class_name,
            'log_level', '2',
            'postRetries', '6',
            'ivehost', self.vpn_host,
            'home_dir', os.path.expanduser('~'),
            'Parameter0', '',
            'user_agent', self.user_agent,
            ], env={'LD_PRELOAD': self.tncc_preload}, stdin=sock, stdout=null)

    def ncsvc_init(self):
        ncLinuxApp_jar = os.path.expanduser('~/.juniper_networks/ncLinuxApp.jar')
        self.ncsvc_bin = os.path.expanduser('~/.juniper_networks/ncsvc')
        self.ncsvc_preload = os.path.expanduser('~/.juniper_networks/ncsvc_preload.so')
        try:
            if zipfile.ZipFile(ncLinuxApp_jar, 'r').testzip() is not None:
                raise Exception()
        except:
            # Note, we need the authenticated connection to download this jar
            print 'Downloading ncLinuxApp.jar...'
            mkdir_p(os.path.expanduser('~/.juniper_networks'))
            self.br.retrieve('https://' + self.vpn_host + '/dana-cached/nc/ncLinuxApp.jar',
                        ncLinuxApp_jar)

        with zipfile.ZipFile(ncLinuxApp_jar, 'r') as jar:
            jar.extract('ncsvc', os.path.expanduser('~/.juniper_networks/'))

        os.chmod(self.ncsvc_bin, 0755)

        if not os.path.isfile(self.ncsvc_preload):
            raise Exception('Missing', self.ncsvc_preload)

        # FIXME: This should really be form the webclient connection,
        # and the web client should verify the cert

        s = socket.socket()
        s.connect((self.vpn_host, 443))
        ss = ssl.wrap_socket(s)
        cert = ss.getpeercert(True)
        self.certfile = os.path.expanduser('~/.juniper_networks/' + self.vpn_host
                                      + '.cert')
        with open(self.certfile, 'w') as f:
            f.write(cert)

    def ncsvc_start(self):
        if self.ncsvc_bin is None:
            self.ncsvc_init()

        dsid_cookie = self.find_cookie('DSID')
        p = subprocess.Popen([self.ncsvc_bin,
            '-h', self.vpn_host,
            '-c', 'DSID=' + dsid_cookie.value,
            '-f', self.certfile,
            '-p', str(self.socks_port),
            '-l', '0',
            ], env={'LD_PRELOAD': self.ncsvc_preload})
        ret = p.wait()
        # 9 - certificate mismatch
        # 6 - closed after being open for a while
        #   - could not connect to host
        # 3 - incorrect DSID
        return ret

def cleanup():
    os.killpg(0, signal.SIGTERM)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler='resolve')
    parser.add_argument('-h', '--host', type=str,
                        help='VPN host name')
    parser.add_argument('-u', '--user', type=str,
                        help='User name')
    parser.add_argument('-o', '--oath', type=str,
                        help='OATH key for two factor authentication (hex)')
    parser.add_argument('-p', '--socks_port', type=int, default=1080,
                        help='Socks proxy port (default: %(default))')
    parser.add_argument('-c', '--config', type=str,
                        help='Config file for the script')

    args = parser.parse_args()
    password = None
    oath = None

    if args.config is not None:
        config = ConfigParser.RawConfigParser()
        config.read(args.config)
        try:
            args.user = config.get('vpn', 'username')
        except:
            pass
        try:
            args.host = config.get('vpn', 'host')
        except:
            pass
        try:
            password = config.get('vpn', 'password')
        except:
            pass
        try:
            oath = config.get('vpn', 'oath')
        except:
            pass
        try:
            args.socks_port = config.get('vpn', 'socks_port')
        except:
            pass

    if args.user == None or args.host == None:
        print "--user and --host are required parameters"
        sys.exit(1)

    atexit.register(cleanup)
    jvpn = juniper_vpn_wrapper(args.host, args.user, password, oath, args.socks_port)
    jvpn.run()

