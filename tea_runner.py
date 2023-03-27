#!/usr/bin/env python3

"""
Run tasks based on webhooks configured in Gitea.

Command-line options:
    --debug, -d  Send more detailed log output to console.

Configuration file (config.ini) options:

    [runner]
    ALLOWED_IP_RANGE=xxx.xxx.xxx.xxx/mm
    # Only respond to requests made from this range of IP addresses. Eg. 192.168.1.0/24
    GIT_SSL_NO_VERIFY=true
    # Ignore certificate host verification errors. Useful for self-signed certs.
    LISTEN_IP=xxx.xxx.xxx.xxx
    # IP address for incoming requests. Defaults to 0.0.0.0 (Any).
    LISTEN_PORT=xxxx
    # TCP port number used for incoming requests. Defaults to 1706.
"""

from ipaddress import ip_address, ip_network
from subprocess import run, DEVNULL
from sys import exit
from os import access, X_OK, chdir, environ, path, system
from tempfile import TemporaryDirectory
from waitress import serve
from werkzeug import utils
from flask import Flask, request, jsonify
from configparser import ConfigParser
from argparse import ArgumentParser
import logging

GIT_BIN = '/usr/bin/git'
RSYNC_BIN = '/usr/bin/rsync'
DOCKER_BIN = '/usr/bin/docker'

print("Tea Runner")


# Debug is a command-line option, but most configuration comes from config.ini
arg_parser = ArgumentParser()
arg_parser.add_argument('-d', '--debug', action='store_true',
                        help='display debugging output while running')
arg_parser.add_argument('-p', '--port', dest='port', type=int,
                        help='port to run the server on', metavar='port', default=1706)
arg_parser.add_argument('-s', '--ssh', dest='ssh', type=bool,
                        help='if you want the request to be in ssh', metavar='ssh', default=False)

args = arg_parser.parse_args()

config = ConfigParser()
config.read('config.ini')

allowed_commands = []

if config.get('runner', 'ALLOWED_COMMANDS', fallback='') != '':
    allowed_commands = config.get('runner', 'ALLOWED_COMMANDS', fallback='').split(' | ')

if args.debug:
    config.set('runner', 'DEBUG', "true")

if args.ssh:
    config.set('runner', 'TYPE', "ssh")

if config.getboolean('runner', 'DEBUG', fallback='False') == True:
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.DEBUG)
    logging.info('Debug logging is on')
else:
    logging.basicConfig(
        format='%(levelname)s: %(message)s', level=logging.INFO)

if not access(GIT_BIN, X_OK):
    logging.error("git binary not found or not executable")
    exit(1)
if not access(RSYNC_BIN, X_OK):
    logging.error("rsync binary not found or not executable")
    exit(1)
if not access(DOCKER_BIN, X_OK):
    logging.error("docker binary not found or not executable")
    exit(1)


def git_clone(src_url, dest_dir):
    """
    Clone a remote git repository into a local directory.

    Args:
        src_url (string): HTTP(S) url used to clone the repo.
        dest_dir (string): Path to the local directory.

    Returns:
       (boolean): True if command returns success.
    """

    logging.info('git clone ' + src_url)
    if config.getboolean('runner', 'GIT_SSL_NO_VERIFY', fallback='False') == True:
        environ['GIT_SSL_NO_VERIFY'] = 'true'
    chdir(dest_dir)
    clone_result = run([GIT_BIN, 'clone', src_url, '.'],
                       stdout=None if args.debug else DEVNULL, stderr=None if args.debug else DEVNULL)
    return clone_result.returncode == 0


app = Flask(__name__)


@app.before_request
def check_authorized():
    """
    Only respond to requests from ALLOWED_IP_RANGE if it's configured in config.ini
    """
    if config.has_option('runner', 'ALLOWED_IP_RANGE'):
        allowed_ip_range = ip_network(config['runner']['ALLOWED_IP_RANGE'])
        requesting_ip = ip_address(request.remote_addr)
        if requesting_ip not in allowed_ip_range:
            logging.info(
                'Dropping request from unauthorized host ' + request.remote_addr)
            return jsonify(status='forbidden'), 403
        else:
            logging.info('Request from ' + request.remote_addr)


@app.before_request
def check_media_type():
    """
    Only respond requests with Content-Type header of application/json
    """
    if not request.headers.get('Content-Type').lower().startswith('application/json'):
        logging.error(
            '"Content-Type: application/json" header missing from request made by ' + request.remote_addr)
        return jsonify(status='unsupported media type'), 415


@app.route('/test', methods=['POST'])
def test():
    logging.debug('Content-Type: ' + request.headers.get('Content-Type'))
    logging.debug(request.get_json(force=True))
    return jsonify(status='success', sender=request.remote_addr)


@app.route('/rsync', methods=['POST'])
def rsync():
    body = request.get_json()
    dest = request.args.get('dest') or body['repository']['name']
    got_commands = [] if request.args.get('command') == None else request.args.get('command').split(';') if request.args.get('command').split(';')[-1] != '' else request.args.get('command').split(';')[:-1]
    commands = set(allowed_commands).intersection(got_commands)
    rsync_root = config.get('rsync', 'RSYNC_ROOT', fallback='')
    clone_url = body['repository']['ssh_rl'] if config.get('runner', 'TYPE', fallback='https').lower() == 'ssh' else body['repository']['clone_url'] if config.get(
        'cred', 'USERNAME', fallback='') == '' and config.get('cred', 'PASSWORD', fallback='') == '' else ''.join([body['repository']['clone_url'].split('://')[0] , '://' , config.get('cred', 'USERNAME', fallback='') , ':' , config.get('cred', 'PASSWORD', fallback='') , '@' , body['repository']['clone_url'].split('://')[1]])

    if rsync_root:
        dest = path.join(rsync_root, utils.secure_filename(dest))
        logging.debug('rsync dest path updated to ' + dest)

    with TemporaryDirectory() as temp_dir:
        if git_clone(clone_url, temp_dir):
            logging.info('rsync ' + body['repository']['name'] + ' to ' + dest)
            chdir(temp_dir)
            if config.get('rsync', 'DELETE', fallback=''):
                result = run([RSYNC_BIN, '-r',
                              '--exclude=.git',
                              '--delete-during' if config.get(
                                  'rsync', 'DELETE', fallback='') else '',
                              '.',
                              dest],
                             stdout=None if args.debug else DEVNULL,
                             stderr=None if args.debug else DEVNULL
                             )
            else:
                result = run([RSYNC_BIN, '-r',
                              '--exclude=.git',
                              '.',
                              dest],
                             stdout=None if args.debug else DEVNULL,
                             stderr=None if args.debug else DEVNULL
                             )
            if result.returncode != 0:
                return jsonify(status='rsync failed'), 500
            else:
                if commands != None:
                    system('cd '+dest + ';' + " && ".join(commands))
        else:
            return jsonify(status='git clone failed'), 500

    return jsonify(status='success')


@app.route('/docker/build', methods=['POST'])
def docker_build():
    body = request.get_json()

    with TemporaryDirectory() as temp_dir:
        if git_clone(body['repository']['clone_url'], temp_dir):
            logging.info('docker build')
            chdir(temp_dir)
            result = run([DOCKER_BIN, 'build', '-t', body['repository']['name'], '.'],
                         stdout=None if args.debug else DEVNULL, stderr=None if args.debug else DEVNULL)
            if result.returncode != 0:
                return jsonify(status='docker build failed'), 500
        else:
            return jsonify(status='git clone failed'), 500

    return jsonify(status='success')


if __name__ == '__main__':
    logging.info('Limiting requests to: ' + config.get('runner',
                 'ALLOWED_IP_RANGE', fallback='<any>'))
    serve(app, host=config.get('runner', 'LISTEN_IP', fallback='0.0.0.0'),
          port=config.getint('runner', 'LISTEN_PORT', fallback=args.port))
