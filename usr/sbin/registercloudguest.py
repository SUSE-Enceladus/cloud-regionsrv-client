#!/usr/bin/python3

# Copyright (c) 2024, SUSE LLC, All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

"""This script obtains information from the configured region server in the
   cloud environment and uses the information to register the guest with
   the SMT server based on the information provided by the region server.

   The configuration is in INI format and is located in
   /etc/regionserverclnt.cfg

   Logic:
   1.) Check if we are in the same region
       + Comparing information received from the region server and the
         cached data
   2.) Check if already registered
   3.) Register"""

import argparse
import ipaddress
import json
import logging
import os
import requests
import subprocess
import sys
import time
import urllib.parse
import urllib3
import uuid

import cloudregister.registerutils as utils

from cloudregister import smt
from lxml import etree
from requests.auth import HTTPBasicAuth

# Disable the urllib warnings
# We have server certs that have no subject alt names
# We have to check the server state API without certificate validation
urllib3.disable_warnings()
registration_returncode = 0

# ----------------------------------------------------------------------------
def get_register_cmd():
    """Determine which command we need to use to register the system"""

    register_cmd = '/usr/sbin/SUSEConnect'
    # Figure out if we are on RO transactional-update system
    p = subprocess.Popen(
        ['findmnt', '--noheadings', '--json', '/'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    res = p.communicate()
    # If we get an error from findmnt move forward on a best effort basis
    if p.returncode:
        logging.warning('Unable to find filesystem information for "/"')
    else:
        fsinfo = json.loads(res[0])
        fsdata = fsinfo.get('filesystems')
        if fsdata:
            fsoptions = fsdata[0].get('options')
            # If we are on a RO system we need to use the
            # transactional-update command
            if 'ro' in fsoptions.split(','):
                cmd_name = 'transactional-update'
                for path in ['/sbin/','/usr/sbin/']:
                    exec_path = path + cmd_name
                    if os.path.exists(exec_path):
                        register_cmd = exec_path
                        break
                else:
                    err_msg = 'transactional-update command not found.'
                    err_msg += 'But is required on a RO filesystem for '
                    err_msg += 'registration'
                    logging.error(err_msg)
                    print(err_msg, file=sys.stderr)
                    sys.exit(1)

    return register_cmd
    
# ----------------------------------------------------------------------------
def register_modules(extensions, products, registered=[], failed=[]):
    """Register modules obeying dependencies"""
    global registration_returncode
    register_cmd = get_register_cmd()
    for extension in extensions:
        # If the extension is recommended it gets installed with the
        # baseproduct registration. No need to run another registration
        if extension.get('recommended'):
            register_modules(
                extension.get('extensions'), products, registered, failed
            )
            continue
        arch = extension.get('arch')
        identifier = extension.get('identifier')
        version = extension.get('version')
        triplet = '/'.join((identifier, version, arch))
        if triplet in products and triplet not in registered:
            registered.append(triplet)
            if 'transactional' in register_cmd:
                cmd = [
                    register_cmd,
                    'register',
                    '--url',
                    'https://%s' % registration_target.get_FQDN(),
                    '--product',
                    triplet
                ]
            else:
                cmd = [
                    register_cmd,
                    '--url',
                    'https://%s' % registration_target.get_FQDN(),
                    '--product',
                    triplet
                ]
            if os.path.exists(instance_data_filepath):
                cmd.append('--instance-data')
                cmd.append(instance_data_filepath)

            logging.info('Registration: %s' % ' '.join(cmd))
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            res = p.communicate()
            if p.returncode:
                registration_returncode = p.returncode
                error_message = res[0].decode()
                if (
                    registration_returncode == 67 and
                    'registration code' in error_message.lower()
                ):
                    # SUSEConnect sets the following exit codes:
                    # 0:  Registration successful
                    # 64: Connection refused
                    # 65: Access error, e.g. files not readable
                    # 66: Parser error: Server JSON response was not parseable
                    # 67: Server responded with error: see log output
                    failed.append(triplet)
                    # the registration should not be considered failed
                    # because of extra modules registered
                    registration_returncode = 0
                else:
                    logging.error('\tRegistration failed: %s' % error_message)

        register_modules(
            extension.get('extensions'), products, registered, failed
        )

def cleanup():
    """Remove any registration artifacts"""
    utils.clean_registry_setup()
    utils.remove_registration_data()
    utils.clean_smt_cache()
    utils.clear_new_registration_flag()
    utils.clean_framework_identifier()


# ----------------------------------------------------------------------------
argparse = argparse.ArgumentParser(description='Register on-demand instance')
argparse.add_argument(
    '--clean',
    action='store_true',
    dest='clean_up',
    default=False,
    help='Clean up registration data'
)
argparse.add_argument(
    '-d', '--delay',
    default=0,
    dest='delay_time',
    help='Delay the start of registration by given value in seconds',
    type=int
)
# default config file location not set it is encoded in the utils function
# get_config(()
argparse.add_argument(
    '-f', '--config-file',
    dest='config_file',
    help='Path to config file, default: /etc/regionserverclnt.cfg',
)
argparse.add_argument(
    '--force-new',
    action='store_true',
    dest='force_new_registration',
    default=False,
    help='Force a new registration, for exceptional cases only',
)
help_msg='The target update server cert fingerprint. '
help_msg+='Use in exceptional cases only'
argparse.add_argument(
    '--smt-fp',
    dest='user_smt_fp',
    help=help_msg
)
help_msg='The target update server FQDN. '
help_msg+='Use in exceptional cases only'
argparse.add_argument(
    '--smt-fqdn',
    dest='user_smt_fqdn',
    help=help_msg
)
help_msg='The target update server IP. '
help_msg+='Use in exceptional cases only'
argparse.add_argument(
    '--smt-ip',
    dest='user_smt_ip',
    help=help_msg
)
help_msg='Email address for product registration'
argparse.add_argument(
    '-e', '--email',
    dest='email',
    help=help_msg
)
help_msg='The registration code'
argparse.add_argument(
    '-r', '--regcode',
    dest='reg_code',
    help=help_msg
)
argparse.add_argument(
    '-v', '--version',
    action='version',
    version='{version}'.format(
        version=open(
            os.path.join(
                os.path.dirname(smt.__file__),
                'VERSION'
            )
        ).read().strip()
    )
)


args = argparse.parse_args()

if args.user_smt_ip or args.user_smt_fqdn or args.user_smt_fp:
    if not (args.user_smt_ip and args.user_smt_fqdn and args.user_smt_fp):
        msg = '--smt-ip, --smt-fqdn, and --smt-fp must be used together'
        print(msg, file=sys.stderr)
        sys.exit(1)

    try:
        ipaddress.ip_address(args.user_smt_ip)
    except ValueError as err:
        msg = "--smt-ip value '{ip_addr}' is not correct: {err}".format(
            ip_addr=args.user_smt_ip,
            err=err
        )
        print(msg, file=sys.stderr)
        sys.exit(1)

    if not utils.has_network_access_by_ip_address(args.user_smt_ip):
        error_message = (
            'Connection error: Could not establish a connection to {ip}.'
            'Please, make sure the network configuration supports the '
            'provided {ip} address version.'.format(ip=args.user_smt_ip)
        )
        sys.exit(error_message)


if args.clean_up and args.force_new_registration:
    msg = '--clean and --force-new are incompatible, use one or the other'
    print(msg, file=sys.stderr)
    sys.exit(1)

    # Specifying reg code only works, but an e-mail requires a reg code
if (args.email and not args.reg_code):
    msg = '--email and --regcode must be used together'
    print(msg, file=sys.stderr)
    sys.exit(1)

time.sleep(int(args.delay_time))

config_file = args.config_file
if config_file:
    config_file = os.path.expanduser(args.config_file)
cfg = utils.get_config(config_file)
utils.start_logging()

if args.clean_up:
    logging.info('Registration clean up initiated by user')
    cleanup()
    sys.exit(0)

if not os.path.isdir(utils.get_state_dir()):
    os.makedirs(utils.get_state_dir())

utils.set_new_registration_flag()
if args.force_new_registration:
    logging.info('Forced new registration')

if args.user_smt_ip:
    msg = 'Using user specified SMT server:\n'
    msg += '\n\t"IP:%s"' % args.user_smt_ip
    msg += '\n\t"FQDN:%s"' % args.user_smt_fqdn
    msg += '\n\t"Fingerprint:%s"' % args.user_smt_fp
    logging.info(msg)

cached_smt_servers = utils.get_available_smt_servers()
if cached_smt_servers:
    # If we have an update server cache the system is registered in
    # some way shape or form
    utils.clear_new_registration_flag()
else:
    utils.write_framework_identifier(cfg)

# Forced registration or user specified SMT, clear existing registration
# data
if (args.force_new_registration and cached_smt_servers) or args.user_smt_ip:
    if utils.is_zypper_running():
        msg = 'zypper is running: Registration with the update '
        msg += 'infrastructure is only possible if zypper is not running.\n'
        msg += 'Please re-run the force registration process after zypper '
        msg += 'has completed'
        print(msg)
        sys.exit(1)
    cleanup()
    utils.set_new_registration_flag()
    utils.write_framework_identifier(cfg)
    cached_smt_servers = []

# Proxy setup
proxies = None
proxy = utils.set_proxy()
if proxy:
    http_proxy = os.environ.get('http_proxy')
    https_proxy = os.environ.get('https_proxy')
    no_proxy = os.environ.get('no_proxy')
    proxies = {'http_proxy': http_proxy,
               'https_proxy': https_proxy,
               'no_proxy': no_proxy}
    logging.info('Using proxy settings: %s' % proxies)

if args.user_smt_ip:
    smt_xml = '<regionSMTdata><smtInfo '
    smt_xml += 'fingerprint="%s" ' % args.user_smt_fp
    smt_ip = ipaddress.ip_address(args.user_smt_ip)
    if isinstance(smt_ip, ipaddress.IPv6Address):
        smt_xml += 'SMTserverIPv6="%s" ' % args.user_smt_ip
    elif isinstance(smt_ip, ipaddress.IPv4Address):
        smt_xml += 'SMTserverIP="%s" ' % args.user_smt_ip
    smt_xml += 'SMTserverName="%s" ' % args.user_smt_fqdn
    registry_fqdn = 'registry-{}'.format(args.user_smt_fqdn.split('-')[1])
    smt_xml += 'SMTregistryName="%s"' % registry_fqdn
    smt_xml += '/></regionSMTdata>'
    region_smt_data = etree.fromstring(smt_xml)
else:
    region_smt_data = utils.fetch_smt_data(cfg, proxies)

registration_smt = utils.get_current_smt()

# Check if we are in the same region
region_smt_servers = cached_smt_servers
region_change = utils.has_region_changed(cfg)
if region_change and utils.uses_rmt_as_scc_proxy():
    # We do not have the users registration code, stay connected to the
    # servers in a different region.
    # If the user also moved to a new framework registration will be broken
    # due to the instance data.
    # This code is a safe guard in case a user enabled the service on a BYOS
    # instance, which is not supposed to be the case or tries
    print('Region change detected:')
    print('\tSystem uses SCC credentials, please re-register the system'
                 ' to the update infrastrusture in this region\n'
                 '\tregistercloudguest --clean\n'
                 '\tregistercloudguest -r YOUR_REG_CODE')
elif region_change:
    logging.info('Region change detected, registering to new servers')
    cleanup()
    region_smt_servers = cached_smt_servers = []
    registration_smt = None
    utils.set_new_registration_flag()
    utils.write_framework_identifier(cfg)

if not region_smt_servers:
    cnt = 1
    for child in region_smt_data:
        smt_server = smt.SMT(child, utils.https_only(cfg))
        region_smt_servers.append(smt_server)
        # Write the available servers to cache as well
        utils.store_smt_data(
            os.path.join(
                utils.get_state_dir(),
                utils.AVAILABLE_SMT_SERVER_DATA_FILE_NAME % cnt
            ),
            smt_server
        )
        cnt +=1

# Check if the target RMT for the registration is alive or if we can
# find a server that is alive in this region
if registration_smt:
    registration_smt_cache_file_name = (
        os.path.join(
            utils.get_state_dir(),
            utils.REGISTERED_SMT_SERVER_DATA_FILE_NAME
        )
    )
    updated = utils.update_rmt_cert(registration_smt)
    alive = registration_smt.is_responsive()
    if alive:
        msg = 'Instance is registered, and update server is reachable, '
        msg += 'nothing to do'
        # The cache data may have been cleared, write if necessary
        if not os.path.exists(registration_smt_cache_file_name) or updated:
            utils.store_smt_data(
                registration_smt_cache_file_name,
                registration_smt
            )
            if not utils.has_rmt_in_hosts(registration_smt):
                utils.clean_hosts_file(registration_smt.get_domain_name())
                utils.add_hosts_entry(registration_smt)
        logging.info(msg)
        sys.exit(0)
    else:
        # The current target server is not resposive, lets check if we can
        # find another server
        for new_target in region_smt_servers:
            if (
                    not new_target.is_responsive() or
                    not registration_smt.is_equivalent()
            ):
                continue
            smt_ip = new_target.get_ipv4()
            if utils.has_rmt_ipv6_access(new_target):
                smt_ip = new_target.get_ipv6()
            msg = 'Configured update server is unresponsive, switching '
            msg += 'to equivalent update server with ip %s' % smt_ip
            utils.replace_hosts_entry(registration_smt, new_target)
            utils.store_smt_data(
                registration_smt_cache_file_name,
                new_target
            )
            utils.update_rmt_cert(new_target)
            break
        else:
            msg = 'Configured update server is unresponsive. Could not find '
            msg += 'a replacement update server in this region. '
            msg += 'Possible network configuration issue'
            logging.error(msg)
            sys.exit(1)

# We should not get here for a registered system that is a proxy. However,
# it doesn't hurt to check and get out before breaking things
if utils.uses_rmt_as_scc_proxy():
    logging.info('System already uses the update infrastructure with a '
                 'registration code, nothing to do')
    sys.exit(0)

# Figure out which server is responsive and use it as registration target
registration_target = None
tested_smt_servers = []
for smt_srv in region_smt_servers:
    tested_smt_servers.append((smt_srv.get_ipv4(), smt_srv.get_ipv6()))
    alive = smt_srv.is_responsive()
    if alive:
        registration_target = smt_srv
        utils.set_as_current_smt(smt_srv)
        # Use the first server that responds
        break

if not registration_target:
    logging.error('No response from: %s' % str(tested_smt_servers))
    sys.exit(1)

# Create location to store data if it does not exist
if not os.path.exists(utils.get_state_dir()):
    os.system('mkdir -p %s' % utils.get_state_dir())

# Write the data of the current target server
utils.set_as_current_smt(registration_target)

# Check if we need to send along any instance data
instance_data_filepath = os.path.join(utils.get_state_dir(), str(uuid.uuid4()))
instance_data = utils.get_instance_data(cfg)
if instance_data:
    inst_data_out = open(instance_data_filepath, 'w')
    inst_data_out.write(instance_data)
    inst_data_out.close()

# Check if registration is supported
if not utils.is_registration_supported(cfg):
    sys.exit(0)

register_cmd = get_register_cmd()
if not (os.path.exists(register_cmd) and os.access(register_cmd, os.X_OK)):
    err_msg = 'No registration executable found'
    logging.error(err_msg)
    print(err_msg, file=sys.stderr)
    sys.exit(1)

# get product list
products = utils.get_installed_products()
if products is None:
    logging.error('No products installed on system')
    sys.exit(1)

if not utils.import_smt_cert(registration_target):
    logging.error('SMT certificate import failed')
    sys.exit(1)

# Register the base product first
base_registered = False
failed_smts = []

while not base_registered:
    utils.add_hosts_entry(registration_target)
    sub_cmd = ''
    if 'transactional' in register_cmd:
        cmd = [
            register_cmd,
            'register',
            '--url',
            'https://%s' % registration_target.get_FQDN()
        ]
    else:
        cmd = [
            register_cmd,
            '--url',
            'https://%s' % registration_target.get_FQDN()
        ]
    if os.path.exists(instance_data_filepath):
        cmd.append('--instance-data')
        cmd.append(instance_data_filepath)
    if args.email:
        cmd.append('--email')
        cmd.append(args.email)
    if args.reg_code:
        cmd.append('--regcode')
        cmd.append(args.reg_code)
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    res = p.communicate()
    if p.returncode:
        registration_returncode = p.returncode
        # Even on error SUSEConnect writes messages to stdout, go figure
        error_message = res[0].decode()
        failed_smts.append(registration_target.get_ipv4())
        if (
            len(failed_smts) == len(region_smt_servers) or
            (registration_returncode == 67 and
             'registration code' in error_message.lower() and
             args.reg_code)
        ):
            # there are no more RMT servers to try to register to or
            # registration failed because of an invalid reg code
            # and that SCC response will not change, independently
            # of the RMT sibling selected
            # SCC exit codes:
            # 0: Registration successful
            # 64: Connection refused
            # 65: Access error, e.g. files not readable
            # 66: Parser error: Server JSON response was not parseable
            # 67: Server responded with error: see log output
            logging.error('Baseproduct registration failed')
            logging.error('\t%s' % error_message)
            cleanup()
            print(error_message, file=sys.stderr)
            sys.exit(1)
        for smt_srv in region_smt_servers:
            target_smt_ipv4 = registration_target.get_ipv4()
            target_smt_ipv6 = registration_target.get_ipv6()
            new_smt_ipv4 = smt_srv.get_ipv4()
            new_smt_ipv6 = smt_srv.get_ipv6()
            if (
                    smt_srv.get_ipv4() != \
                    registration_target.get_ipv4() and
                    smt_srv.get_ipv4() not in failed_smts
            ):
                error_msg = 'Registration with %s failed. Trying %s'
                logging.error(
                    error_msg % (
                        str((target_smt_ipv4, target_smt_ipv6)),
                        str((new_smt_ipv4, new_smt_ipv6))
                    )
                )
                utils.remove_registration_data()
                utils.clean_hosts_file(registration_target.get_domain_name())
                registration_target = smt_srv
                break
    else:
        logging.info('Baseproduct registration complete')
        base_registered = True
        utils.clear_new_registration_flag()
        if args.email or args.reg_code:
            utils.set_rmt_as_scc_proxy_flag()

base_prod_xml = open('/etc/products.d/baseproduct').read()
prod_def_start = base_prod_xml.index('<product')
product_tree = etree.fromstring(base_prod_xml[prod_def_start:])
prod_identifier = product_tree.find('name').text.lower()
version = product_tree.find('version').text
arch = product_tree.find('arch').text
headers = {'Accept': 'application/vnd.scc.suse.com.v4+json'}
query_args = 'identifier=%s&version=%s&arch=%s' % (
    prod_identifier, version, arch)
user, password = utils.get_credentials(
    utils.get_credentials_file(registration_target)
)
auth_creds = HTTPBasicAuth(user, password)
res = requests.get(
    'https://%s/connect/systems/products?%s' % (
        registration_target.get_FQDN(), query_args
    ),
    auth=auth_creds,
    headers=headers
)
if res.status_code != 200:
    err_msg = 'Unable to obtain product information from server "%s"\n'
    err_msg += '\t%s\n\t%s\nUnable to register modules, exiting.'
    ips = '%s,%s' % (
        registration_target.get_ipv4(), registration_target.get_ipv6()
    )
    logging.error(err_msg % (ips, res.reason, res.content.decode("UTF-8")))
    sys.exit(1)

prod_data = json.loads(res.text)
extensions = prod_data.get('extensions')
failed_extensions = []
register_modules(extensions, products, failed=failed_extensions)

if os.path.exists(instance_data_filepath):
    os.unlink(instance_data_filepath)

if registration_returncode:
    cleanup()
    print(
        'Registration failed, see /var/log/cloudregister for details',
        file=sys.stderr
    )
    sys.exit(registration_returncode)

if not utils.setup_registry(
    registration_target.get_registry_FQDN(), user, password
):
    cleanup()
    sys.exit('Registration failed, see /var/log/cloudregister for details')

print('Registration succeeded')

if failed_extensions:
    print(
        'There are products that were not registered because they need '
        'an additional registration code, to register them please run '
        'the following command:'
    )
    activate_prod_cmd = 'SUSEConnect -p {} -r ADDITIONAL REGCODE'
    for failed_extension in failed_extensions:
        print(activate_prod_cmd.format(failed_extension))

# Enable Nvidia repo if repo(s) are configured and destination can be reached
if utils.has_nvidia_support():
    nvidia_repo_names = utils.find_repos('nvidia')
    for repo_name in nvidia_repo_names:
        url = urllib.parse.urlparse(utils.get_repo_url(repo_name))
        cmd = ['ping', '-c', '2', url.hostname]
        if utils.exec_subprocess(cmd):
            msg = 'Cannot reach host: "%s", will not enable repo "%s"'
            logging.info(msg % (url.hostname, repo_name))
        else:
            utils.enable_repository(repo_name)

utils.switch_services_to_plugin()
