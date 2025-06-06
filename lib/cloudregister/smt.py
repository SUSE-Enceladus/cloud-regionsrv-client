# Copyright (c) 2023, SUSE LLC, All rights reserved.
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

"""Class to hold the information we need to connect and identify an SMT
   server."""

import ipaddress
import logging
import os
import requests

from M2Crypto import X509


class SMT:
    """Store smt information"""
    def __init__(self, smtXMLNode, https_only=False):
        self._ipv4 = None
        try:
            self._ipv4 = smtXMLNode.attrib['SMTserverIP']
        except KeyError:
            pass
        self._ipv6 = None
        try:
            self._ipv6 = smtXMLNode.attrib['SMTserverIPv6']
        except KeyError:
            pass
        try:
            self._region = smtXMLNode.attrib['region']
        except KeyError:
            self._region = 'unknown'
        try:
            self._registry_fqdn = smtXMLNode.attrib['SMTregistryName']
        except KeyError:
            self._registry_fqdn = ''
        self._fqdn = smtXMLNode.attrib['SMTserverName']
        self._fingerprint = smtXMLNode.attrib['fingerprint']
        self._cert = None
        self._cert_names = ('smt.crt', 'rmt.crt')
        self._protocol = 'http'
        if https_only:
            self._protocol = 'https'
        self._check_urls = self._form_srv_check_urls()
        # disable InsecureRequestWarning
        # as verification is disabled for the https request
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )

    # --------------------------------------------------------------------
    def __eq__(self, other_smt):
        if not isinstance(other_smt, SMT):
            return False
        if (
                self.get_ipv4() == other_smt.get_ipv4() and
                self.get_ipv6() == other_smt.get_ipv6() and
                self.get_FQDN() == other_smt.get_FQDN() and
                self.get_registry_FQDN() == other_smt.get_registry_FQDN() and
                self.get_fingerprint() == other_smt.get_fingerprint() and
                self.get_region() == other_smt.get_region()
        ):
            return True

        return False

    # --------------------------------------------------------------------
    def __ne__(self, other_smt):
        return not self.__eq__(other_smt)

    # --------------------------------------------------------------------
    def get_cert(self):
        """Return the CA certificate for the SMT server"""
        if not self._cert:
            cert_rq = self.__request_cert()
            if cert_rq:
                cert = cert_rq.text
                if self.__is_cert_valid(cert):
                    self._cert = cert

        return self._cert

    # --------------------------------------------------------------------
    def get_domain_name(self):
        """Return the domain name for the server."""
        return self._fqdn.split('.', 1)[-1]

    # --------------------------------------------------------------------
    def get_fingerprint(self):
        """Return the fingerprint of the cert"""
        return self._fingerprint

    # --------------------------------------------------------------------
    def get_FQDN(self):
        """Return the fully qualified domain name"""
        return self._fqdn

    # --------------------------------------------------------------------
    def get_registry_FQDN(self):
        """Return the fully qualified domain registry name"""
        return self._registry_fqdn if hasattr(self, '_registry_fqdn') else ''

    # --------------------------------------------------------------------
    def get_name(self):
        """Return the name"""
        return self._fqdn.split('.', 1)[0]

    # --------------------------------------------------------------------
    def get_ipv4(self):
        """Return the IP address"""
        # Before handling ipv6 the IP address was stored in the _ip
        # member. When the SMT object is restored from an old pickeled
        # file the _ip member gets created while the _ipv4 member does
        # not exist. Handle this transition properly.
        if hasattr(self, '_ip'):
            self._ipv4 = self._ip
        return self._ipv4

    # --------------------------------------------------------------------
    def get_ipv6(self):
        """Return the IP address"""
        # Before handling ipv6 the IP address was stored in the _ip
        # member. When the SMT object is restored from an old pickeled
        # file the _ipv6 member does not exist. Handle this transition
        # properly.
        if not hasattr(self, '_ipv6'):
            return None
        return self._ipv6

    # --------------------------------------------------------------------
    def get_region(self):
        """Return the region name this server is associated with"""
        return self._region

    # --------------------------------------------------------------------
    def is_equivalent(self, smt_server):
        """Have both an ipv4 address and/or both an ipv6 address and they
           are in the same region they are interchangeable and considered
           equivalent"""
        if (
                ((self.get_ipv4() and smt_server.get_ipv4()) or
                 (self.get_ipv6() and smt_server.get_ipv6())) and
                self.get_region() == smt_server.get_region()
        ):
            return True

        return False

    # --------------------------------------------------------------------
    def is_responsive(self):
        """Check if the SMT server is responsive"""
        # We cannot know if the server cert has been imported into the
        # system cert hierarchy, nor do we know if the hostname is resolvable
        # or if the IP address is built into the cert. Since we only want
        # to know if the system is responsive we ignore cert validation
        # Using the IP address protects us from hostname spoofing
        for health_url in self._check_urls.keys():
            try:
                response = requests.get(health_url, timeout=2, verify=False)
                if response.status_code == 200:
                    status = response.json()
                    return status.get('state') == 'online'
                elif response.status_code == 404:
                    cert_url = self._check_urls.get(health_url)
                    # We are pointing to an SMT server, the health status API
                    # is not available. Download the cert to at least make sure
                    # Apache is responsive
                    for cert_name in self._cert_names:
                        cert_response = requests.get(
                            cert_url + cert_name, verify=False
                        )
                        if cert_response and cert_response.status_code == 200:
                            return True
            except Exception:
                # Something is wrong with the server
                pass

        return False

    # --------------------------------------------------------------------
    def set_protocol(self, protocol):
        """Method to set the protocol to use for certain queries.
           http and https are allowed. This is used to update
           cached server data to provide an upgrade path for systems
           that want to switch to https only."""

        if protocol not in ('http', 'https'):
            return

        self._protocol = protocol

    # --------------------------------------------------------------------
    def write_cert(self, target_dir):
        """Write the certificate to the given directory"""
        logging.info('Writing SMT rootCA: %s' % target_dir)
        cert = self.get_cert()
        certs_to_write = []
        ipv4 = self.get_ipv4()
        if ipv4:
            certs_to_write.append(ipv4.replace('.', '_'))
        ipv6 = self.get_ipv6()
        if ipv6:
            certs_to_write.append(ipv6.replace(':', '_'))
        ca_file_path = os.path.join(target_dir, 'registration_server_%s.pem')
        # We write the cert twice one time with the IPv4 as identifier and
        # one time with the IPv6 as identifier. This is not an indication that
        # the update server can be reached over both protocols.
        # Changing the naming convention to something generic so we could
        # write the cert only once would break SUMa as it looks for the certs
        # we write here with the known pattern.
        for cert_name in certs_to_write:
            try:
                with open(ca_file_path % cert_name, 'w') as smt_ca_file:
                    smt_ca_file.write(cert)
            except IOError:
                errMsg = 'Could not store update server certificate'
                logging.error(errMsg)
                return 0

        return 1

    # Private
    # --------------------------------------------------------------------
    def _form_srv_check_urls(self):
        """Form the access urls for server health checks"""
        srv_ips = (self.get_ipv6(), self.get_ipv4())
        check_urls = {}
        for srv_ip in srv_ips:
            if not srv_ip:
                continue
            rmt_ip = srv_ip
            # Per rfc3986 IPv6 addresses in a URI are enclosed in []
            if isinstance(ipaddress.ip_address(rmt_ip), ipaddress.IPv6Address):
                rmt_ip = '[%s]' % srv_ip
            health_url = 'https://%s/api/health/status' % rmt_ip
            cert_url = '%s://%s/' % (self._protocol, rmt_ip)
            check_urls[health_url] = cert_url

        return check_urls

    # --------------------------------------------------------------------
    def __is_cert_valid(self, cert):
        """Verify that the fingerprint of the given cert matches the
           expected fingerprint"""
        try:
            x509 = X509.load_cert_string(str(cert))
            x509_fingerprint = x509.get_fingerprint('sha1')
        except Exception:
            errMsg = 'Could not read X509 fingerprint from cert'
            logging.error(errMsg)
            return False

        if x509_fingerprint != self.get_fingerprint().replace(':', ''):
            errMsg = 'Fingerprint could not be verified'
            logging.error(errMsg)
            return False

        return True

    # --------------------------------------------------------------------
    def __request_cert(self):
        """Request the cert from the SMT server and return the request"""
        cert_res = None
        attempts = 0
        retries = 3
        while attempts < retries:
            attempts += 1
            for cert_name in self._cert_names:
                for cert_url in self._check_urls.values():
                    try:
                        cert_res = requests.get(
                            cert_url + cert_name, verify=False
                        )
                    except Exception:
                        # No response from server

                        logging.warning('+' * 20)
                        # Extract the IP address we tried
                        ip = 'unkown'
                        if '[' in cert_url:
                            ip = self.get_ipv6()
                        else:
                            ip = self.get_ipv4()
                        logging.warning('Server %s is unreachable' % ip)
                    if cert_res:
                        if cert_res.status_code == 200:
                            logging.info(
                                'Request to %s%s succeeded' %
                                (cert_url, cert_name)
                            )
                            return cert_res

                        logging.warning(
                            'Request to %s%s failed: %s' %
                            (cert_url, cert_name, cert_res.status_code)
                        )
