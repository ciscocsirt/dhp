import sys
import argparse
import os
import tempfile

__copyright__ = """

    Copyright 2020 Cisco Systems, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

"""
__license__ = "Apache 2.0"


def create_certs(ca_name='server_ca', common_name:str=None, common_names:list=None, 
                 output_path="./ssl/", ca_path=None):

    common_names = common_names if common_names else []

    if common_name and common_name not in common_names:
        common_names.append(common_name)

    with tempfile.TemporaryDirectory() as tmpdirname:
        kargs = {
            "tmpdirname": os.path.join(tmpdirname, 'certstrap'),
            "ca_path": ca_path,
            "bin_dir": os.path.join(tmpdirname, 'certstrap/bin'),
            "out_dir": output_path,
            "ca_name": ca_name,
            "ca_key_path": os.path.join(output_path, "{}.key".format(ca_name)),
            "ca_crl_path": os.path.join(output_path, "{}.crl".format(ca_name)),
            "ca_crt_path": os.path.join(output_path, "{}.crt".format(ca_name)),
            "certstrap_url": "https://github.com/square/certstrap/releases/download/v1.2.0/certstrap-1.2.0-linux-amd64",
            "certstrap_bin": "{}/certstrap".format(os.path.join(tmpdirname, 'certstrap/bin')),
            "output_path": output_path,
        }


        os.system("mkdir -p {output_path}".format(**kargs))
        os.system("mkdir -p {bin_dir}".format(**kargs))
        os.system("curl -fLs -o {certstrap_bin} {certstrap_url}".format(**kargs))
        os.system("chmod +x {certstrap_bin}".format(**kargs))
        os.system('mkdir -p ./out/')
        if ca_path:
            os.system('cp {ca_path}/{ca_name}*  ./out/'.format(**kargs))
        else:
            os.system('{certstrap_bin} init --passphrase "" --common-name {ca_name} --expires "100 years"'.format(**kargs))

        os.system('cp ./out/{ca_name}.crt {ca_crt_path}'.format(**kargs))
        os.system('cp ./out/{ca_name}.crl {ca_crl_path}'.format(**kargs))
        os.system('cp ./out/{ca_name}.key {ca_key_path}'.format(**kargs))
        for common_name in common_names:
            kargs.update({
                "common_name": common_name,
                "cert_path": os.path.join(output_path, "{}-cert.pem".format(common_name)), 
                "key_path": os.path.join(output_path, "{}-key.pem".format(common_name)),
                "combined_path": os.path.join(output_path, "{}.pem".format(common_name)), 
            })

            os.system('{certstrap_bin} request-cert --passphrase "" --common-name {common_name}'.format(**kargs))
            os.system('{certstrap_bin} sign {common_name} --passphrase "" --CA {ca_name} --expires "100 years"'.format(**kargs))
            os.system('cp ./out/{common_name}.crt {cert_path}'.format(**kargs))
            os.system('cp ./out/{common_name}.key {key_path}'.format(**kargs))
            os.system('cat {key_path} {cert_path} > {combined_path}'.format(**kargs))
    
    os.system('rm -rf ./out/'.format(**kargs))


parser = argparse.ArgumentParser()

parser.add_argument("-ca_name", help="ca name", default=None)
parser.add_argument("-ca_path", help="path to ca info", default=None)

parser.add_argument("-common_names", help="common names to create", nargs="+", default=None)
parser.add_argument("-common_name", help="common name to create", default=None)
parser.add_argument("-output_path", help="path to put everything in", default="./ssl")

if __name__ == '__main__':
    args = parser.parse_args()
    dargs = vars(args)

    if args.ca_name is None:
        parser.print_help()
        sys.exit(-1)
    elif args.common_name is None and args.common_names is None:
        parser.print_help()
        sys.exit(-1)

    create_certs(**dargs)