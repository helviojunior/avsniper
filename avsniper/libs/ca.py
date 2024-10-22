import base64, time, random
import hashlib
import json
from typing import Union, List, Optional, Iterable

import cryptography.x509
from OpenSSL import crypto
from OpenSSL.crypto import dump_certificate, dump_publickey, FILETYPE_ASN1, FILETYPE_PEM, PKCS7, X509, X509Name, \
    X509Extension
from asn1crypto import core
from asn1crypto import x509 as ans1x509
from asn1crypto.cms import *
from asn1crypto.core import OctetString
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate, SubjectAlternativeName, ExtensionNotFound, AuthorityInformationAccess, \
    AccessDescription, Extension
from asn1crypto.algos import *
from cryptography.hazmat.primitives.serialization import pkcs7


import re

from urllib3.contrib.pyopenssl import _dnsname_to_stdlib

x509NameMap = {
    'CN': 'commonName',
    'C': 'countryName',
    'L': 'localityName',
    'ST': 'stateOrProvinceName',
    'SP': 'stateOrProvinceName',
    'S': 'stateOrProvinceName',
    'O': 'organizationName',
    'OU': 'organizationalUnitName',
    'MAIL': 'emailAddress',
    'E': 'emailAddress',
}


class CA(object):
    ca_cert = None
    ca_key = None

    def __init__(self):
        pass

    @staticmethod
    def load_pkcs7(data: Union[bytes, bytearray]) -> PKCS7:
        pkcs7 = None
        try:
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, b'' + data)
        except:
            pass

        if pkcs7 is None:
            try:
                pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, b'' + data)
            except:
                pass

        if pkcs7 is None:
            raise Exception('Error loading PKCS#7')

        return pkcs7

    @staticmethod
    def get_pkcs7_certificates(bundle: PKCS7) -> Optional[List[Certificate]]:
        """
            Extracts X.509 certificates from an OpenSSL PKCS7 object.

            Args:
                bundle (OpenSSL PKCS7 object) : PKCS7 object to extract the certificates from.

            Returns:
                A tuple containing the extracted certificates
                (cryptography X.509 certificates, not OpenSSL X.509 certificates!)

            """

        from OpenSSL._util import (
            ffi as _ffi,
            lib as _lib
        )

        pkcs7_certs = _ffi.NULL
        if bundle.type_is_signed():
            pkcs7_certs = bundle._pkcs7.d.sign.cert
        elif bundle.type_is_signedAndEnveloped():
            pkcs7_certs = bundle._pkcs7.d.signed_and_enveloped.cert

        certificates: List[Certificate] = []
        for i in range(_lib.sk_X509_num(pkcs7_certs)):
            certificate = X509.__new__(X509)
            certificate._x509 = _ffi.gc(_lib.X509_dup(_lib.sk_X509_value(pkcs7_certs, i)), _lib.X509_free)
            certificates.append(certificate.to_cryptography())
            certificate.to_cryptography().extensions
        if not certificates:
            return None
        return certificates

    @staticmethod
    def get_cert_data_array(bundle: Union[bytes, bytearray]) -> dict:
        cert = None
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, bundle).to_cryptography()
        except:
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, bundle).to_cryptography()
            except:
                pass

        if cert is None:
            return {}

        return {
            'Serial': str(cert.serial_number),
            'Subject': next((
                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                            in cert.subject.rdns
                            if 'cn=' in s.rfc4514_string().lower()
                        ), cert.subject.rfc4514_string()),
            'Issuer': next((
                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                            in cert.issuer.rdns
                            if 'cn=' in s.rfc4514_string().lower()
                        ), cert.issuer.rfc4514_string()),
            'Fingerprint': (''.join([
                                f'{x:02x}' for x in cert.fingerprint(hashes.SHA1())
                            ])),
            'Data': b'' + bundle
        }

    @staticmethod
    def get_pkcs7_human_data(bundle: Union[bytes, bytearray]) -> dict:
        raw_data = CA.get_pkcs7_data(bundle)
        data = {}

        data['Hash algorithm'] = raw_data['digest_algorithm']
        data['Hash'] = ''.join([
                                    f'{x:02x}' for x in raw_data.get('signed_attrs', {}).get('message_digest', [])
                                ])
        data['Signed content'] = raw_data.get('content_info', {}).get('content', b'')
        data['Signature'] = raw_data['signature']

        data['Attributes'] = {}

        att = raw_data.get('unsigned_attrs', {})
        if isinstance(att, dict):
            for k, v in att.items():
                data['Attributes'][k] = {
                    'Type': v['content_type'],
                    'Content info': v.get('encap_content_info', {}).get('content', ''),
                    'Signer info (Hash)': ''.join([
                                f'{x:02x}' for x in v.get('signer_infos', [{}])[0].get('signed_attrs', {}).get('message_digest', b'')
                            ]),
                    'Signer info (Signature)': v.get('signer_infos', [{}])[0].get('signature', b'')
                }

                data['Attributes'][k].update({
                    f'Certificate {idx} ({cdk})': cdd
                    for idx, c in enumerate(v.get('certificates', {}))
                    for cdk, cdd in CA.get_cert_data_array(v['certificates'][c]).items()
                })

        return data

    @staticmethod
    def get_pkcs7_data(bundle: Union[bytes, bytearray]) -> dict:
        from asn1crypto import cms, core

        data = {
            'signed_attrs': {},
            'content_info': {},
            'unsigned_attrs': {},
        }

        # extract the needed structures
        content_info: cms.ContentInfo = cms.ContentInfo.load(b'' + bundle)
        signed_data: cms.SignedData = content_info['content']
        signer_info: cms.SignerInfo = signed_data['signer_infos'][0]

        for name in signed_data['encap_content_info']:
            data['content_info'][name] = CA.get_attribute_value(signed_data['encap_content_info'][name])

        data.update(CA.get_attribute_value(signer_info))

        return data

    @staticmethod
    def get_attribute_data(attr: CMSAttributes, level=0):
        value = attr['values'][0]

        if isinstance(attr['type'], CMSAttributeType):
            name = str(CMSAttributeType.map(attr['type'].__unicode__()))

            value = CA.get_attribute_value(value, level)

            if len(name.split('.')) > 4:
                return None, None

        else:

            name = str(attr['type'].native)
            value = value.native

        return name, value

    @staticmethod
    def get_attribute_value(value, level=0):
        if isinstance(value, ContentType):
            return ContentType.map(value.__unicode__())

        elif isinstance(value, CMSVersion):
            return str(value.native)

        elif isinstance(value, SetOfOctetString) or isinstance(value, OctetString):
            return value.__bytes__()

        elif isinstance(value, DigestAlgorithms):
            if len(value) > 0:
                if isinstance(value[0], DigestAlgorithm):
                    return DigestAlgorithmId.map(value[0]['algorithm'].__unicode__())

        elif isinstance(value, DigestAlgorithm):
            return DigestAlgorithmId.map(value['algorithm'].__unicode__())

        elif isinstance(value, SignedDigestAlgorithm):
            return SignedDigestAlgorithmId.map(value['algorithm'].__unicode__())

        elif isinstance(value, core.Any):
            return value.dump()

        if level > 5:
            return value.dump()

        if isinstance(value, ContentInfo):
            n_value = {
                'content_type': CA.get_attribute_value(value['content_type'])
            }
            for ci_name in value['content']:
                n_value[ci_name] = CA.get_attribute_value(value['content'][ci_name])

            return n_value

        elif isinstance(value, EncapsulatedContentInfo):
            return {
                'content_type': CA.get_attribute_value(value['content_type']),
                'content': value['content'].dump()
            }

        elif isinstance(value, CertificateSet):
            n_value = {}
            for cs in value:
                cert = cs.chosen
                n_value[cert.serial_number] = cert.dump()

            return n_value

        elif isinstance(value, CMSAttributes):
            n_value = {}

            for attr in value:
                name, v1 = CA.get_attribute_data(attr, level + 1)
                if name is not None:
                    n_value['unsigned_attrs'][name] = v1

            return n_value

        elif isinstance(value, SignerInfos):
            return [
                CA.get_attribute_value(i, level + 1) for i in value
                if i is not None and isinstance(i, SignerInfo)
            ]

        elif isinstance(value, SignerInfo):
            n_value = {
                'version': CA.get_attribute_value(value['version']),
                'signature': value['signature'].dump(),
                'signature_algorithm': CA.get_attribute_value(value['signature_algorithm']),
                'digest_algorithm': CA.get_attribute_value(value['digest_algorithm']),
                'signed_attrs': {},
                'unsigned_attrs': {}
            }

            signed_attrs: List[CMSAttributes] = value['signed_attrs']
            for signed_attr in signed_attrs:

                name, v1 = CA.get_attribute_data(signed_attr, level + 1)
                if name is not None:
                    n_value['signed_attrs'][name] = v1

            unsigned_attrs: List[CMSAttributes] = value['unsigned_attrs']
            for unsigned_attr in unsigned_attrs:

                name, v1 = CA.get_attribute_data(unsigned_attr, level + 1)
                if name is not None:
                    n_value['unsigned_attrs'][name] = v1

            return n_value

        return value.native

    @staticmethod
    def get_ocsp_urls(x509cert: Certificate) -> List[str]:
        url_list = []
        try:
            aia_extension = x509cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value

            # pylint: disable=protected-access
            for aia_method in iter([aia_extension]):
                if isinstance(aia_method, AuthorityInformationAccess):
                    for acd in aia_method:
                        if acd.__getattribute__("access_method")._name.lower() in ("ocsp", "caissuers"):
                            url_list.append(acd.__getattribute__("access_location").value)
                elif isinstance(aia_method, AccessDescription):
                    if aia_method.__getattribute__("access_method")._name.lower() in ("ocsp", "caissuers"):
                        url_list.append(aia_method.__getattribute__("access_location").value)

        except ExtensionNotFound:
            pass

        return url_list

    @staticmethod
    def get_certificate_san(x509cert: Certificate) -> List[str]:
        san = []
        # <Extension(oid=<ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)>, critical=False, value=<SubjectAlternativeName(<GeneralNames([<RFC822Name(value='contato@sec4us.com.br')>])>)>)>

        try:
            ext = x509cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value
            if ext is not None:
                # pylint: disable=protected-access
                if isinstance(ext, SubjectAlternativeName):
                    for v in ext:
                        san += [
                            s.strip() for s in v.value.lower().replace('\n', ',').replace('\r', '').replace(';', ',').split(',')
                            if s.strip() != ''
                        ]

        except cryptography.x509.extensions.ExtensionNotFound:
            pass

        return san

    @staticmethod
    def parse_dn(s) -> X509Name:
        """Parse a string into a X509Name"""
        x509Name = X509Name(crypto.X509().get_subject())

        # need to handle escaping of the RHS, etc.
        prog = re.compile(u'([A-Z0-9.]+)=(.*)')
        for pair in s.replace('/', ',').split(','):
            match = prog.fullmatch(pair)
            if match:
                (name, value) = match.group(1, 2)
                if name in x509NameMap:
                    x509Name.__setattr__(x509NameMap[name], value)
                else:
                    x509Name.__setattr__(name, value)

        return x509Name

    @staticmethod
    def get_certificate_san2(x509cert: Certificate) -> List[tuple[str, str]]:

        try:
            ext = x509cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value
            if ext is not None:
                # pylint: disable=protected-access
                if isinstance(ext, SubjectAlternativeName):
                    yield from [
                        ("DNS", name)
                        for name in map(_dnsname_to_stdlib, ext.get_values_for_type(crypto.x509.DNSName))
                        if name is not None
                    ]
                    yield from [
                        ("IP Address", str(name))
                        for name in ext.get_values_for_type(crypto.x509.IPAddress)
                    ]
                    yield from [
                        ("email", str(name))
                        for name in ext.get_values_for_type(crypto.x509.RFC822Name)
                    ]
                    yield from [
                        ("uri", str(name))
                        for name in ext.get_values_for_type(crypto.x509.UniformResourceIdentifier)
                    ]
                    # TODO: Implement to DirectoryName, RegisteredID, OtherName

        except cryptography.x509.extensions.ExtensionNotFound:
            pass

    def create_ca_from_name(self, name: X509Name):
        self.create_ca(**{
            **dict(cn=name.CN),
            **(dict(country=name.C) if name.C is not None and name.C.strip() != '' else {}),
            **(dict(state=name.ST) if name.ST is not None and name.ST.strip() != '' else {}),
            **(dict(city=name.L) if name.L is not None and name.L.strip() != '' else {}),
            **(dict(company=name.O) if name.O is not None and name.O.strip() != '' else {}),
            **(dict(organizational_unit=name.OU) if name.OU is not None and name.OU.strip() != '' else {}),
            **(dict(email=name.emailAddress)
               if name.emailAddress is not None and name.emailAddress.strip() != '' else {})
        })

    def create_ca(self, cn: str,
                  country: str = "BR",
                  state: str = "PR",
                  city: str = "Curitiba",
                  company: str = "Sec4US",
                  organizational_unit: str = "DevOps",
                  email: str = "contato@sec4us.com.br"
                  ):
        if self.ca_cert is None or self.ca_key is None:
            serialnumber = random.getrandbits(64)

            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 4096)

            cert = crypto.X509()
            cert.get_subject().C = country
            cert.get_subject().ST = state
            cert.get_subject().L = city
            cert.get_subject().O = company
            cert.get_subject().OU = organizational_unit
            cert.get_subject().CN = cn
            cert.get_subject().emailAddress = email
            cert.set_serial_number(serialnumber)
            cert.set_version(2)  # Integer 2 is Cert V3
            cert.gmtime_adj_notBefore(-(24 * 60 * 60))
            cert.gmtime_adj_notAfter(15 * 24 * 60 * 60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.add_extensions([
                crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
                crypto.X509Extension(b"keyUsage", False, b"cRLSign, digitalSignature, keyCertSign"),
                crypto.X509Extension(b"extendedKeyUsage", False, b'serverAuth, clientAuth'),
                crypto.X509Extension(b"nsCertType", False, b'server'),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            ])
            cert.sign(k, 'sha256')

            self.ca_cert = cert
            self.ca_key = k

    def create_intermediate_ca(self, name: X509Name):
        if self.ca_cert is None or self.ca_key is None:
            raise Exception("CA not created yet! Check Command create_ca.")

        cert_req = crypto.X509Req()

        for k, v in name.get_components():
            cert_req.get_subject().__setattr__(k.decode("UTF-8"), v)

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)

        cert_req.set_pubkey(k)
        cert_req.sign(self.ca_key, 'sha256')

        cert = crypto.X509()
        cert.set_serial_number(int(time.time()))
        cert.set_version(2)  # Integer 2 is Cert V3
        cert.gmtime_adj_notBefore(-(24 * 60 * 60))
        cert.gmtime_adj_notAfter(15 * 24 * 60 * 60)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_subject(cert_req.get_subject())
        cert.set_pubkey(cert_req.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", False, b"cRLSign, digitalSignature, keyCertSign"),
            crypto.X509Extension(b"extendedKeyUsage", False, b'serverAuth, clientAuth'),
            crypto.X509Extension(b"nsCertType", False, b'server'),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid,issuer", issuer=self.ca_cert)
        ])

        cert.sign(self.ca_key, 'sha256')

        new_ca = CA()
        new_ca.load_ca_cert(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode("UTF-8"))
        new_ca.load_ca_key(base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)).decode("UTF-8"))

        return new_ca

    def get_json(self):

        pub = crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.ca_key)

        data = {
            'ca_cert': base64.b64encode(pub).decode("UTF-8"),
            'ca_key': base64.b64encode(priv).decode("UTF-8")
        }

        return json.dumps(data)

    def load_json(self, json_data):
        data = json.loads(json_data)
        ca_cert = data.get('ca_cert', None)
        ca_key = data.get('ca_key', None)
        if ca_cert is None or ca_key is None:
            raise Exception('ca_cert and ca_key cannot be None')

        self.load_ca_cert(ca_cert)
        self.load_ca_key(ca_key)

    def load_ca_cert(self, b64cert):
        self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, base64.b64decode(b64cert))

    def load_ca_key(self, b64key):
        self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, base64.b64decode(b64key))

    @staticmethod
    def calc_pin_data(b64cert):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, base64.b64decode(b64cert))

        pin_domain = cert.get_subject().commonName.lower()

        der = dump_publickey(FILETYPE_ASN1, cert.get_pubkey())
        if isinstance(der, str):
            der = der.encode("utf-8")

        sha256 = hashlib.sha256(der).digest()
        pin_hash = 'sha256/' + base64.b64encode(sha256).decode("utf-8")

        return pin_domain, pin_hash

    def create_signed_cert(self, name: X509Name,
                           key_usage: X509Extension = None,
                           extended_key_usage: X509Extension = None,
                           subject_alternative_name: Union[str, bytes] = None
                           ):
        if self.ca_cert is None or self.ca_key is None:
            raise Exception("CA not created yet! Check Command create_ca.")

        cert_req = crypto.X509Req()

        for k, v in name.get_components():
            cert_req.get_subject().__setattr__(k.decode("UTF-8"), v)

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)

        cert_req.set_pubkey(k)
        cert_req.sign(self.ca_key, 'sha256')

        cert = crypto.X509()
        cert.set_serial_number(int(time.time()))
        cert.set_version(2)  # Integer 2 is Cert V3
        cert.gmtime_adj_notBefore(-(24 * 60 * 60))
        cert.gmtime_adj_notAfter(15 * 24 * 60 * 60)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_subject(cert_req.get_subject())
        cert.set_pubkey(cert_req.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            key_usage
            if key_usage is not None
            else crypto.X509Extension(b"keyUsage", True, b"nonRepudiation,digitalSignature,keyEncipherment"),
            extended_key_usage
            if extended_key_usage is not None
            else crypto.X509Extension(b"extendedKeyUsage", False, b'clientAuth,emailProtection'),
            crypto.X509Extension(b"nsCertType", False, b'client,email'),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid,issuer", issuer=self.ca_cert)
        ] + ([crypto.X509Extension(b"subjectAltName", False, (
            subject_alternative_name
            if isinstance(subject_alternative_name, bytes) else subject_alternative_name.encode("UTF-8")))]
             if subject_alternative_name is not None else []))

        cert.sign(self.ca_key, 'sha256')

        str_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("UTF-8")
        str_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("UTF-8")

        # pkcs12 = crypto.PKCS12()
        # pkcs12.set_certificate(cert)
        # pkcs12.set_privatekey(k)

        # return pkcs12.export(passphrase=passphrase)

        return str_cert, str_key

    @staticmethod
    def generate_pkcs12(cert: crypto.X509,
                        key: crypto.PKey,
                        passphrase: Union[bytes, str],
                        ca_certificates: Iterable[X509] = None) -> bytes:

        pkcs12 = crypto.PKCS12()
        pkcs12.set_certificate(cert)
        pkcs12.set_privatekey(key)
        if ca_certificates is not None:
            pkcs12.set_ca_certificates(ca_certificates)

        if isinstance(passphrase, str):
            passphrase = passphrase.encode("UTF-8")

        return pkcs12.export(passphrase=passphrase)

    def save_files(self, x509_filename, private_filename):
        pub = crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.ca_key)

        open(x509_filename, "wt").write(pub.decode("utf-8"))
        open(private_filename, "wt").write(priv.decode("utf-8"))

    def get_base64_ca_cert(self):
        pub = crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        return base64.b64encode(pub).decode("UTF-8")
