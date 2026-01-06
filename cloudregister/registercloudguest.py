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
import os
import requests
import sys
import time
import urllib.parse
import uuid

from cloudregister.logger import Logger
from cloudregister.defaults import (
    LOG_FILE,
    ZYPP_SERVICES,
    DOCKER_CONFIG_PATH,
    REGISTERED_SMT_SERVER_DATA_FILE_NAME,
    AVAILABLE_SMT_SERVER_DATA_FILE_NAME
)
import cloudregister.registerutils as utils

from cloudregister import smt
from lxml import etree
from requests.auth import HTTPBasicAuth

__version__ = '10.5.3'

log_instance = Logger()
log = Logger.get_logger()

# Disable the urllib warnings
# We have server certs that have no subject alt names
# We have to check the server state API without certificate validation
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)
registration_returncode = 0


# ----------------------------------------------------------------------------
def register_modules(
    extensions, products, registration_target, instance_data_filepath,
    regcode='', registered=[], failed=[]
):
    """Register modules obeying dependencies"""
    global registration_returncode
    for extension in extensions:
        # If the extension is recommended it gets installed with the
        # baseproduct registration. No need to run another registration
        if extension.get('recommended'):
            register_modules(
                extension.get('extensions'), products, registration_target,
                instance_data_filepath, regcode, registered, failed
            )
            continue

        arch = extension.get('arch')
        identifier = extension.get('identifier')
        version = extension.get('version')
        triplet = '/'.join((identifier, version, arch))
        if triplet in products and triplet not in registered:
            registered.append(triplet)

            prod_reg = utils.register_product(
                registration_target=registration_target,
                regcode=regcode,
                product=triplet,
                instance_data_filepath=instance_data_filepath
            )

            if prod_reg.returncode:
                registration_returncode = prod_reg.returncode
                # Older versions of SUSEConnect wrote error messages to stdout
                error_message = prod_reg.output
                if not error_message:
                    error_message = prod_reg.error
                if (
                    registration_returncode == 67 and
                    (
                        'registration code' in error_message.lower() or
                        'system credentials' in error_message.lower()
                    )
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
                    log.error('\tRegistration failed: %s' % error_message)

        register_modules(
            extension.get('extensions'), products, registration_target,
            instance_data_filepath, regcode, registered, failed
        )


# ----------------------------------------------------------------------------
def cleanup():
    """
    Cleanup registration data. This covers sending
    delete requests to the API servers as well as deletion of
    cache and etc files.
    """
    utils.clean_all_standard()


# ----------------------------------------------------------------------------
def setup_registry(registration_target):
    """
    Run the registration process for the container registry
    """
    user, password = utils.get_credentials(
        utils.get_credentials_file(registration_target)
    )
    registry_fqdn = registration_target.get_registry_FQDN()

    with_docker = utils.is_docker_present()
    if not with_docker:
        log.info(
            'docker config file {} not found. '
            'Registration for docker skipped. '
            'Install docker to add docker support.'.format(
                DOCKER_CONFIG_PATH
            )
        )

    if utils.is_registry_registered(registry_fqdn):
        if with_docker:
            # Special handling for the docker case:
            #
            # When docker is present we perform the registry configuration
            # for the docker container engine. This may cause calling the
            # setup routine even though docker was setup before. However,
            # the code will only effectively write a new registry setup
            # if the required modifications are not included.
            log.info('Adding docker support')
            docker_setup_ok = utils.set_registries_conf_docker(registry_fqdn)

            # docker_setup_ok will take a True/False value on a real
            # action that happened. In any other case a None value is
            # present which indicates no action was performed.
            if docker_setup_ok is False:
                log.error(
                    'Registration failed(docker), see {0} for details'.format(
                        LOG_FILE
                    )
                )
                sys.exit(1)
            elif docker_setup_ok is True:
                log.info('Successfully added docker to the registry setup')
        log.info(
            'Instance is setup to access container registry, nothing to do'
        )
        return True
    log.info(
        'Adding registry setup to instance, all existing shell '
        'sessions must be restarted to use the registry.'
    )
    registry_setup_ok = False
    if utils.prepare_registry_setup(registry_fqdn, user, password):
        log.info('Adding podman support')
        registry_setup_ok = utils.set_registries_conf_podman(registry_fqdn)
        if with_docker:
            log.info('Adding docker support')
            registry_setup_ok = utils.set_registries_conf_docker(registry_fqdn)
        if utils.is_suma_instance():
            registry_setup_ok = utils.set_registry_fqdn_suma(registry_fqdn)
    if not registry_setup_ok:
        log.error(
            'Registration failed(registry), see {0} for details'.format(
                LOG_FILE
            )
        )
        return False
    log.warning('Instance registry setup done, sessions must be restarted !')
    return True


# ----------------------------------------------------------------------------
def get_responding_update_server(region_smt_servers):
    """
    Figure out which update server is responsive
    If no update server responds, exit with an error message
    that lists the tested servers
    """
    tested_smt_servers = []
    for smt_srv in region_smt_servers:
        tested_smt_servers.append((smt_srv.get_ipv4(), smt_srv.get_ipv6()))
        if smt_srv.is_responsive():
            utils.set_as_current_smt(smt_srv)
            return smt_srv
    log.error(
        'No response from: {}'.format(tested_smt_servers)
    )
    sys.exit(1)


# ----------------------------------------------------------------------------
def setup_ltss_registration(
    registration_target, regcode, instance_data_filepath
):
    """
    Run registration command to register LTSS for this instance
    """
    log.info('Running LTSS registration...')
    log.debug('Running LTSS registration...this takes a little longer')
    product = utils.get_product_tree()
    if product is None:
        message = 'Cannot find baseproduct registration for LTSS'
        log.error(message)
        sys.exit(1)

    ltss_registered = False
    if os.path.isdir(ZYPP_SERVICES):
        for entry in os.listdir(ZYPP_SERVICES):
            if 'LTSS' in entry:
                ltss_registered = True
                break
    if ltss_registered:
        message = 'LTSS registration succeeded'
        log.info(message)
    else:
        base_product = utils.get_product_triplet(product)
        # LTSS registration is always SLES even for variants such as
        # SAP and HPC.
        ltss_product_triplet = 'SLES-LTSS/{0}/{1}'.format(
            base_product.version, base_product.arch
        )

        prod_reg = utils.register_product(
            registration_target=registration_target,
            product=ltss_product_triplet,
            regcode=regcode,
            instance_data_filepath=instance_data_filepath
        )
        if prod_reg.returncode != 0:
            # Something went wrong...
            # Even on error SUSEConnect writes messages to stdout, go figure
            message = prod_reg.output
            log.error(
                'LTSS registration failed see /var/log/cloudregister for details'
            )
            log.debug('\t{0}'.format(message))
            sys.exit(1)
        message = 'LTSS registration succeeded'
        log.info(message)


# ----------------------------------------------------------------------------
def register_base_product(
    registration_target, instance_data_filepath, args, region_smt_servers
):
    """Register the base product and return the RMT update server registered."""
    global registration_returncode
    base_registered = False
    failed_smts = []
    while not base_registered:
        utils.add_hosts_entry(registration_target)
        prod_reg = utils.register_product(
            registration_target=registration_target,
            email=args.email,
            regcode=args.reg_code,
            instance_data_filepath=instance_data_filepath
        )
        if prod_reg.returncode:
            registration_returncode = prod_reg.returncode
            # Even on error SUSEConnect writes messages to stdout, go figure
            error_message = prod_reg.output
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
                log.error('Baseproduct registration failed')
                log.error(error_message)
                utils.deregister_non_free_extensions()
                utils.deregister_from_update_infrastructure()
                utils.deregister_from_SCC()
                utils.clean_hosts_file(
                    registration_target.get_domain_name()
                )
                utils.clean_base_credentials()
                utils.clean_cache()
                sys.exit(1)
            for smt_srv in region_smt_servers:
                target_smt_ipv4 = registration_target.get_ipv4()
                target_smt_ipv6 = registration_target.get_ipv6()
                new_smt_ipv4 = smt_srv.get_ipv4()
                new_smt_ipv6 = smt_srv.get_ipv6()
                if (
                        smt_srv.get_ipv4() != registration_target.get_ipv4() and
                        smt_srv.get_ipv4() not in failed_smts
                ):
                    error_msg = 'Registration with %s failed. Trying %s'
                    log.error(
                        error_msg % (
                            str((target_smt_ipv4, target_smt_ipv6)),
                            str((new_smt_ipv4, new_smt_ipv6))
                        )
                    )
                    utils.clear_rmt_as_scc_proxy_flag()
                    utils.deregister_non_free_extensions()
                    utils.deregister_from_update_infrastructure()
                    utils.deregister_from_SCC()
                    utils.clean_registered_smt_data_file()
                    utils.clean_hosts_file(
                        registration_target.get_domain_name()
                    )
                    registration_target = smt_srv
                    break
        else:
            log.info('Baseproduct registration complete')
            base_registered = True
            utils.clear_new_registration_flag()
            if args.email or args.reg_code:
                utils.set_rmt_as_scc_proxy_flag()

    return registration_target


# ----------------------------------------------------------------------------
def find_alive_registration_target(registration_smt, region_smt_servers):
    target_found = False
    if registration_smt:
        registration_smt_cache_file_name = (
            os.path.join(
                utils.get_state_dir(),
                REGISTERED_SMT_SERVER_DATA_FILE_NAME
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
            # The registry target may be missing, write if necessary
            if not utils.has_registry_in_hosts(registration_smt):
                utils.clean_hosts_file(registration_smt.get_domain_name())
                utils.add_hosts_entry(registration_smt)
            log.info(msg)
            target_found = True
        else:
            # The current target server is not resposive, lets check if we can
            # find another server
            for new_target in region_smt_servers:
                if (
                        not new_target.is_responsive() or
                        not registration_smt.is_equivalent(new_target)
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
                registration_smt = new_target
                target_found = True
                break
            else:
                msg = 'Configured update server is unresponsive. '
                msg += 'Could not find a replacement update server '
                msg += 'in this region. Possible network configuration issue'
                log.error(msg)
                sys.exit(1)

    return registration_smt, target_found


# ----------------------------------------------------------------------------
def make_request(url, registration_target):
    headers = {'Accept': 'application/vnd.scc.suse.com.v4+json'}
    user, password = utils.get_credentials(
        utils.get_credentials_file(registration_target)
    )
    res = requests.get(
        url,
        auth=HTTPBasicAuth(user, password),
        headers=headers
    )
    if res.status_code != 200:
        err_msg = 'Unable to obtain product information from server "%s"\n'
        err_msg += '\t%s\n\t%s\nUnable to register modules, exiting.'
        ips = '%s,%s' % (
            registration_target.get_ipv4(), registration_target.get_ipv6()
        )
        log.error(err_msg % (ips, res.reason, res.content.decode("UTF-8")))
        sys.exit(1)

    return res.json()


# ----------------------------------------------------------------------------
def get_system_products(registration_target):
    base_product = utils.get_product_triplet(
        utils.get_product_tree()
    )
    query_args = 'identifier=%s&version=%s&arch=%s' % (
        base_product.name, base_product.version, base_product.arch
    )
    system_products_url = 'https://%s/connect/systems/products?%s' % (
        registration_target.get_FQDN(), query_args
    )
    # request the system products
    return make_request(system_products_url, registration_target)


# ----------------------------------------------------------------------------
def get_extensions(registration_target):
    prod_data = get_system_products(registration_target)
    return prod_data.get('extensions')


# ----------------------------------------------------------------------------
def get_proxies():
    """Return the proxies set in the environment in a dictionary or None."""
    proxies = None
    if utils.set_proxy():
        http_proxy = os.environ.get('http_proxy')
        https_proxy = os.environ.get('https_proxy')
        no_proxy = os.environ.get('no_proxy')
        proxies = {
            'http_proxy': http_proxy,
            'https_proxy': https_proxy,
            'no_proxy': no_proxy
        }
        log.info('Using proxy settings: %s' % proxies)

    return proxies


# ----------------------------------------------------------------------------
def get_region_smt_data(args, cfg, proxies):
    """Return the region SMT data."""
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
        return etree.fromstring(smt_xml)
    else:
        return utils.fetch_smt_data(cfg, proxies)


# ----------------------------------------------------------------------------
def get_update_servers(region_smt_data, cfg):
    """Return available update servers in a list."""
    region_smt_servers = []
    https_only = utils.https_only(cfg)
    for cnt, child in enumerate(region_smt_data, start=1):
        smt_server = smt.SMT(child, https_only)
        region_smt_servers.append(smt_server)
        # Write the available servers to cache as well
        utils.store_smt_data(
            os.path.join(
                utils.get_state_dir(),
                AVAILABLE_SMT_SERVER_DATA_FILE_NAME % cnt
            ),
            smt_server
        )

    return region_smt_servers


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
    '--debug',
    action='store_true',
    default=False,
    dest='debug',
    help='Increase verbosity of logfile information'
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
help_msg = 'The target update server cert fingerprint. '
help_msg += 'Use in exceptional cases only'
argparse.add_argument(
    '--smt-fp',
    dest='user_smt_fp',
    help=help_msg
)
help_msg = 'The target update server FQDN. '
help_msg += 'Use in exceptional cases only'
argparse.add_argument(
    '--smt-fqdn',
    dest='user_smt_fqdn',
    help=help_msg
)
help_msg = 'The target update server IP. '
help_msg += 'Use in exceptional cases only'
argparse.add_argument(
    '--smt-ip',
    dest='user_smt_ip',
    help=help_msg
)
help_msg = 'Email address for product registration'
argparse.add_argument(
    '-e', '--email',
    dest='email',
    help=help_msg
)
help_msg = 'The registration code'
argparse.add_argument(
    '-r', '--regcode',
    dest='reg_code',
    help=help_msg
)
argparse.add_argument(
    '-v', '--version',
    action='version',
    version=__version__
)


def main(args):
    log.info('registercloudguest {}'.format(__version__))
    global registration_returncode  # noqa: F824
    if args.user_smt_ip or args.user_smt_fqdn or args.user_smt_fp:
        if not (args.user_smt_ip and args.user_smt_fqdn and args.user_smt_fp):
            msg = '--smt-ip, --smt-fqdn, and --smt-fp must be used together'
            log.error(msg)
            sys.exit(1)

        try:
            ipaddress.ip_address(args.user_smt_ip)
        except ValueError as err:
            msg = "--smt-ip value '{ip_addr}' is not correct: {err}".format(
                ip_addr=args.user_smt_ip,
                err=err
            )
            log.error(msg)
            sys.exit(1)

        if not utils.has_network_access_by_ip_address(args.user_smt_ip):
            error_message = (
                'Connection error: Could not establish a connection to {ip}.'
                'Please, make sure the network configuration supports the '
                'provided {ip} address version.'.format(ip=args.user_smt_ip)
            )
            log.error(error_message)
            sys.exit(1)

    if args.clean_up and args.force_new_registration:
        msg = '--clean and --force-new are incompatible, use one or the other'
        log.error(msg)
        sys.exit(1)

    # Specifying reg code only works, but an e-mail requires a reg code
    if (args.email and not args.reg_code):
        msg = '--email and --regcode must be used together'
        log.error(msg)
        sys.exit(1)

    time.sleep(int(args.delay_time))

    config_file = args.config_file
    if config_file:
        config_file = os.path.expanduser(args.config_file)
    cfg = utils.get_config(config_file)

    log_instance.set_logfile(LOG_FILE, args.debug)

    if args.clean_up:
        log.info('Registration clean up initiated by user')
        cleanup()
        sys.exit(0)

    if not os.path.isdir(utils.get_state_dir()):
        os.makedirs(utils.get_state_dir())

    utils.set_new_registration_flag()
    if args.force_new_registration:
        log.info('Forced new registration')

    if args.user_smt_ip:
        msg = 'Using user specified SMT server:\n'
        msg += '\n\t"IP:%s"' % args.user_smt_ip
        msg += '\n\t"FQDN:%s"' % args.user_smt_fqdn
        msg += '\n\t"Fingerprint:%s"' % args.user_smt_fp
        log.info(msg)

    cached_smt_servers = utils.get_available_smt_servers()
    if cached_smt_servers:
        # If we have an update server cache the system is registered in
        # some way shape or form
        utils.clear_new_registration_flag()
        utils.set_registration_completed_flag()
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
            log.warning(msg)
            sys.exit(1)
        cleanup()
        utils.set_new_registration_flag()
        utils.write_framework_identifier(cfg)
        cached_smt_servers = []

    # Proxy setup
    proxies = get_proxies()

    region_smt_data = get_region_smt_data(args, cfg, proxies)
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
        log.warning('Region change detected:')
        log.warning(
            '\tSystem uses SCC credentials, please re-register the system'
            ' to the update infrastrusture in this region\n'
            '\tregistercloudguest --clean\n'
            '\tregistercloudguest -r YOUR_REG_CODE'
        )
    elif region_change:
        log.info('Region change detected, registering to new servers')
        cleanup()
        region_smt_servers = cached_smt_servers = []
        registration_smt = None
        utils.set_new_registration_flag()
        utils.write_framework_identifier(cfg)

    if not region_smt_servers:
        region_smt_servers = get_update_servers(region_smt_data, cfg)

    # Check if the target RMT for the registration is alive or if we can
    # find a server that is alive in this region
    registration_smt, registration_target_found = \
        find_alive_registration_target( 
            registration_smt, region_smt_servers
        )

    # Check if we need to send along any instance data
    instance_data_filepath = ''
    instance_data = utils.get_instance_data(cfg)
    if instance_data:
        instance_data_filepath = os.path.join(
            utils.get_state_dir(), str(uuid.uuid4())
        )
        inst_data_out = open(instance_data_filepath, 'w')
        inst_data_out.write(instance_data)
        inst_data_out.close()

    if registration_target_found:
        # 1. check/setup the container registry for this target
        if not setup_registry(registration_smt):
            utils.clean_registry_setup()
            sys.exit(1)

        # 2. check/setup if we got a regcode which is handled as LTSS
        if args.reg_code:
            setup_ltss_registration(
                registration_smt,
                args.reg_code,
                instance_data_filepath
            )

        # All done, time to leave...
        sys.exit(0)

    # We should not get here for a registered system that is a proxy. However,
    # it doesn't hurt to check and get out before breaking things
    if utils.uses_rmt_as_scc_proxy():
        log.info(
            'System already uses the update infrastructure with a '
            'registration code, nothing to do'
        )
        sys.exit(0)

    # The system is not yet registered, Figure out which server
    # is responsive and use it as registration target
    registration_target = get_responding_update_server(region_smt_servers)

    # Create location to store data if it does not exist
    if not os.path.exists(utils.get_state_dir()):
        os.system('mkdir -p %s' % utils.get_state_dir())

    # Write the data of the current target server
    utils.set_as_current_smt(registration_target)

    # Check if registration is supported
    if not utils.is_registration_supported(cfg):
        sys.exit(0)

    register_cmd = utils.get_register_cmd()
    if not (os.path.exists(register_cmd) and os.access(register_cmd, os.X_OK)):
        err_msg = 'No registration executable found'
        log.error(err_msg)
        sys.exit(1)

    # get product list
    products = utils.get_installed_products()
    if products is None:
        log.error('No products installed on system')
        sys.exit(1)

    if not utils.import_smt_cert(registration_target):
        log.error('SMT certificate import failed')
        sys.exit(1)

    # Register the base product first
    registration_target = register_base_product(
        registration_target, instance_data_filepath, args, region_smt_servers
    )
    extensions = get_extensions(registration_target)
    failed_extensions = []
    register_modules(
        extensions,
        products,
        registration_target,
        instance_data_filepath,
        args.reg_code,
        failed=failed_extensions
    )
    if os.path.exists(instance_data_filepath):
        os.unlink(instance_data_filepath)

    if registration_returncode:
        utils.deregister_non_free_extensions()
        utils.deregister_from_update_infrastructure()
        utils.deregister_from_SCC()
        utils.clean_cache()
        log.error(
            'Registration failed(repository), see {0} for details'.format(
                LOG_FILE
            )
        )
        sys.exit(registration_returncode)

    # Setup container registry
    if not setup_registry(registration_target):
        cleanup()
        sys.exit(1)

    utils.set_registration_completed_flag()

    log.info('Registration succeeded')

    if failed_extensions:
        log.warning(
            'There are products that were not registered because they need '
            'an additional registration code, to register them please run '
            'the following command:'
        )
        activate_prod_cmd = 'SUSEConnect -p {} -r ADDITIONAL REGCODE'
        if utils.is_transactional_system():
            activate_prod_cmd = 'transactional-update register -p {} '
            activate_prod_cmd += '-r ADDITIONAL REGCODE'
        for failed_extension in failed_extensions:
            log.error(activate_prod_cmd.format(failed_extension))

    # Enable Nvidia repo if repo(s) are configured
    # and destination can be reached
    if utils.has_nvidia_support():
        nvidia_repo_names = utils.find_repos('nvidia')
        for repo_name in nvidia_repo_names:
            url = urllib.parse.urlparse(utils.get_repo_url(repo_name))
            cmd = ['ping', '-c', '2', url.hostname]
            if utils.exec_subprocess(cmd):
                msg = (
                    'Cannot reach host: "{hostname}", '
                    'will not enable repo "{repo_name}"'
                ).format(hostname=url.hostname, repo_name=repo_name)
                log.info(msg)
            else:
                utils.enable_repository(repo_name)


def app():  # pragma: no cover
    args = argparse.parse_args()
    main(args)
