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

def mkdir_p(path):
    try:
        os.mkdir(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def tncc(host, dspreauth, dssignin):

    class_names = ('net.juniper.tnc.NARPlatform.linux.LinuxHttpNAR',
                   'net.juniper.tnc.HttpNAR.HttpNAR')
    class_name = None

    tncc_jar = os.path.expanduser('~/.juniper_networks/tncc.jar')
    try:
        if zipfile.ZipFile(tncc_jar, 'r').testzip() is not None:
            raise Exception()
    except:
        print 'Downloading tncc.jar...'
        mkdir_p(os.path.expanduser('~/.juniper_networks'))
        urllib.urlretrieve('https://' + host
                           + '/dana-cached/hc/tncc.jar', tncc_jar)

    with zipfile.ZipFile(tncc_jar, 'r') as jar:
        for name in class_names:
            try:
                jar.getinfo(name.replace('.', '/') + '.class')
                class_name = name
                break
            except:
                pass

    if class_name is None:
        raise Exception('Could not find class name for', tncc_jar)

    tncc_preload = \
        os.path.expanduser('~/.juniper_networks/tncc_preload.so')
    if not os.path.isfile(tncc_preload):
        raise Exception('Missing', tncc_preload)

    p = subprocess.Popen(['java',
        '-classpath', tncc_jar, class_name,
        'log_level', '2',
        'postRetries', '6',
        'ivehost', host,
        'home_dir', os.path.expanduser('~'),
        'Parameter0', '',
        'user_agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1',
        ], env={'LD_PRELOAD': tncc_preload}, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (stdout, stderr) = p.communicate('start\n' + 'IC=' + host
            + '\nCookie=' + dspreauth + '\nDSSIGNIN=' + dssignin + '\n')

    results = stdout.split('\n', 5)
    if len(results) < 5:
        raise Exception('tncc returned insuficent results', results)

    result = results[1]
    if result != '200':
        raise Exception('tncc returned non 200 code')

    return results[3]


def ncsvc(br, host, cookie, socks_port):
    ncLinuxApp_jar = os.path.expanduser('~/.juniper_networks/ncLinuxApp.jar')
    ncsvc_bin = os.path.expanduser('~/.juniper_networks/ncsvc')
    ncsvc_preload = os.path.expanduser('~/.juniper_networks/ncsvc_preload.so')
    try:
        if zipfile.ZipFile(ncLinuxApp_jar, 'r').testzip() is not None:
            raise Exception()
    except:
        print 'Downloading ncLinuxApp.jar...'
        mkdir_p(os.path.expanduser('~/.juniper_networks'))
        br.retrieve('https://' + host + '/dana-cached/nc/ncLinuxApp.jar',
                    ncLinuxApp_jar)

    with zipfile.ZipFile(ncLinuxApp_jar, 'r') as jar:
        jar.extract('ncsvc', os.path.expanduser('~/.juniper_networks/'))

    os.chmod(ncsvc_bin, 0755)

    if not os.path.isfile(ncsvc_preload):
        raise Exception('Missing', ncsvc_preload)

    # FIXME: This should really be form the webclient connection,
    # and the web client should verify the cert

    s = socket.socket()
    s.connect((host, 443))
    ss = ssl.wrap_socket(s)
    cert = ss.getpeercert(True)
    certfile = os.path.expanduser('~/.juniper_networks/' + host
                                  + '.cert')
    with open(certfile, 'w') as f:
        f.write(cert)

    os.execve(ncsvc_bin, [ncsvc_bin,
        '-h', vpn_host,
        '-c', 'DSID=' + dsid_cookie.value,
        '-f', certfile,
        '-p', str(socks_port),
        '-l', '0',
        ], {'LD_PRELOAD': ncsvc_preload})
    raise Exception('Failed to exec ncsvc')


def find_cookie(cj, name):
    for cookie in cj:
        if cookie.name == name:
            return cookie
    return None

parser = argparse.ArgumentParser(conflict_handler='resolve')
parser.add_argument('-h', '--host', type=str, required=True,
                    help='VPN host name')
parser.add_argument('-u', '--user', type=str, required=True,
                    help='User name')
parser.add_argument('-p', '--socks_port', type=int, default=1080,
                    help='Socks proxy port (default: %(default))')

args = parser.parse_args()

vpn_host = args.host
username = args.user
socks_port = args.socks_port

# Browser
br = mechanize.Browser()

# Cookie Jar
cj = cookielib.LWPCookieJar()
br.set_cookiejar(cj)

# Browser options
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)

# Follows refresh 0 but not hangs on refresh > 0
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                      max_time=1)

# Want debugging messages?
# br.set_debug_http(True)
# br.set_debug_redirects(True)
# br.set_debug_responses(True)

br.addheaders = [('User-agent',
                 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
                 )]

# Open landing page
r = br.open('https://' + vpn_host)

while True:
    dsid_cookie = find_cookie(cj, 'DSID')
    if dsid_cookie:
        ncsvc(br, vpn_host, dsid_cookie.value, socks_port)

    action = 'tncc'
    for form in br.forms():
        if form.name == 'frmLogin':
            action = 'login'
        elif form.name == 'frmDefender':
            action = 'key'
        else:
            raise Exception('Unknown form type:', form.name)
        break

    if action == 'tncc':

        # Run tncc host checker
        dspreauth_cookie = find_cookie(cj, 'DSPREAUTH')
        if dspreauth_cookie is None:
            raise Exception('Could not find DSPREAUTH key for host checker')

        dssignin_cookie = find_cookie(cj, 'DSSIGNIN')
        dssignin = (dssignin_cookie.value if dssignin_cookie else 'null')
        dspreauth = tncc(vpn_host, dspreauth_cookie.value, dssignin)
        if dspreauth is None:
            raise Exception('Host checker failed')
        dspreauth_cookie.value = dspreauth
        cj.set_cookie(dspreauth_cookie)

        # Submit cooke from tncc host checker
        r = br.open(r.geturl())

    elif action == 'login':

        password = getpass.getpass('Password:')

        # Enter username/password
        br.select_form(nr=0)
        br.form['username'] = username
        br.form['password'] = password
        r = br.submit()

    elif action == 'key':

        key = getpass.getpass('Two-factor key:')

        # Enter key
        br.select_form(nr=0)
        br.form['password'] = key
        r = br.submit()

