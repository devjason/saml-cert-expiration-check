from datetime import datetime
from OpenSSL import crypto
import argparse
import requests
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description="Check expiration of X.509 certifactes for SAML")
parser.add_argument('source', help='where to read certificate string without PEM headers', choices=('cmdline', 'url'))
parser.add_argument('data', help='the data for the source')


def construct_pasted_strcert(strcert: str):
    PEM_HEADER = "-----BEGIN CERTIFICATE-----"
    PEM_FOOTER = "-----END CERTIFICATE-----"
    str_pem_cert = '\n'.join([PEM_HEADER, strcert, PEM_FOOTER])
    return str_pem_cert


def fetch_certs_from_url(url):
    response = requests.get(url)
    if response.status_code != requests.codes.ok:
        raise Exception(f'Unable to fetch from URL {url}, status code was {response.status_code}')
    root = ET.fromstring(response.text)

    ns = {
        'md': "urn:oasis:names:tc:SAML:2.0:metadata",
        'ds': 'http://www.w3.org/2000/09/xmldsig#'
    }
    return [e.text for e in root.findall('.//ds:X509Certificate', ns)]



def process_cert(str_pem_cert: str):
    cert : crypto.X509 = crypto.load_certificate(crypto.FILETYPE_PEM, str_pem_cert)
    name : crypto.X509Name = cert.get_issuer()
    # print(str_pem_cert)
    not_after_raw = cert.get_notAfter().decode("utf-8")
    not_after = datetime.strptime(not_after_raw, "%Y%m%d%H%M%SZ")
    print()
    print('Issuer: ', name)
    print('Subject: ', cert.get_subject())
    print('Not after: ', not_after)


if __name__ == "__main__":
    args = parser.parse_args()
    if args.source == 'cmdline':
        strcerts = [args.data]
    elif args.source == 'url':
        strcerts = fetch_certs_from_url(args.data)
    else:
        raise Exception("Invalid source specified")

    print('************************')
    results = [process_cert(cert) for cert in [construct_pasted_strcert(strcert) for strcert in strcerts]]    
