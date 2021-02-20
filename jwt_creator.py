#!/usr/bin/env python3
"""JWT creator as a script"""
__author__ = "PsykoCat"
__maintainer__ = "PsykoCat"
__email__ = __author__ + "at nomail dot localhost"
__license__ = "Apache License 2.0"
__version__ = "0.0.1"

import argparse
import logging
import sys
import json
import jwt

################################################################################
# Internal definitions
################################################################################

################################################################################
# Public definitions
################################################################################
def decode_payload(payload_encoded, secret, algorithm, insecure_check=False):
    """Generate and validate the payload"""
    output = None
    _decode_options = {}
    if insecure_check:
        _decode_options.update({"verify_signature": False})

    try:
        output = jwt.decode(payload_encoded.strip(), secret,
                 algorithms=[algorithm], options=_decode_options)
    except jwt.exceptions.InvalidSignatureError as e:
        logging.error("Bad secret privided.")
        sys.exit(1)
    except jwt.exceptions.DecodeError as e:
        logging.error("Wrong token format provided")
        sys.exit(1)
    return output

def encode_payload(payload_txt, secret, algorithm):
    """Generate and validate the payload"""
    payload = json.loads(payload_txt)
    encoded = jwt.encode(payload,
            secret,
            algorithm=algorithm)
    return encoded

def list_algorithms():
    """Generate and validate the payload"""
    logging.info("Valid list of algorithms")
    for __algo in jwt.PyJWS().get_algorithms():
        print(__algo)

################################################################################
# Main related functions
################################################################################
def _parse_args(**kwargs):
    """Global parser, will provide common options
    but the parse_args is to be made by the caller"""
    parser = argparse.ArgumentParser(**kwargs)
    base_opts = parser.add_argument_group("Base options")
    base_opts.add_argument("-v", "--verbose", dest="verbosity",
                           action="store_const", default=logging.INFO,
                           const=logging.DEBUG, help="Be verbose")
    base_opts.add_argument("-q", "--quiet", dest="verbosity",
                           action="store_const", const=logging.ERROR,
                           help="Be quiet")
    base_opts.add_argument("--version", action="version",
                           version="%(prog)s " + __version__)
    base_opts.add_argument("--no-color", dest="log_color", action="store_false",
                           help="Disable colorful logs")
    base_opts.add_argument("--color", dest="log_color", action="store_true",
                           help="Have colorful logs")
    base_opts.add_argument("-n", "--dry-run", dest="dryrun",
                           action="store_true", help="Dry run")
    return parser

def _setup_log(opts):
    """Basic log setup config, with color customization"""
    verbosity = opts.verbosity
    has_color = opts.log_color

    # Color definitions
    clr_default = "\033[m"
    clr_red = "\033[31m"
    clr_green = "\033[32m"
    clr_yellow = "\033[33m"

    # Define log level decoration for messages
    if not has_color:
        clr_red = clr_yellow = clr_green = clr_default = ""

    # Associate log level with decoration
    level_colors_d = {
        logging.CRITICAL: clr_red + "[C] ",
        logging.ERROR: clr_red + "[E] ",
        logging.WARNING: clr_yellow + "[W] ",
        logging.INFO: clr_green + "[I] ",
        logging.DEBUG: clr_default + "",
    }

    if verbosity is None:
        verbosity = logging.INFO

    # Assigning colors to levels
    fmt = "%(levelname)s%(message)s" + clr_default
    # For each log level specified, set its corresponding visual
    for (log_level, log_deco) in level_colors_d.items():
        logging.addLevelName(log_level, log_deco)
    # Configure logging system
    logging.basicConfig(format=fmt, level=verbosity, stream=sys.stderr)

def parse_args(args=None, **kwargs):
    """Main parse_args caller with specific options"""
    parser = _parse_args(**kwargs)
    # parser.add_argument("", ..., default="", help="")
    parser.add_argument("-a", "--algorithm", default="HS256",
                           help="Algorithm to use")
    parser.add_argument("-s", "--secret", default="",
                           help="Secret to use")
    parser.add_argument("-d", "--decode", action="store_true",
                           help="Decode contents")
    parser.add_argument("-e", "--encode", action="store_true",
                           help="Encode contents")
    parser.add_argument("-l", "--list-algorithms", action="store_true",
                           help="List valid algorithms")
    parser.add_argument("-i", "--insecure-check", action="store_true",
                           help="Allow skipping signature check")
    parser.add_argument("-t", "--test", action="store_true",
                           help="Validate encoded token")
    parser.add_argument("json_payloads", nargs="*", default=[sys.stdin],
                           help="Json payload")
    return (parser, parser.parse_args(args))

def main(args=None):
    """Main part"""
    (_parser, opts) = parse_args(args)
    ret = None
    _setup_log(opts)

    payload = None
    if opts.list_algorithms:
        list_algorithms()
    else:
        for __cfgfile in opts.json_payloads:
            if isinstance(__cfgfile, str):
                with open(__cfgfile, "r") as pl_file:
                    payload = pl_file.read()
            else:
                payload = __cfgfile.read()

            if opts.decode:
                ret = decode_payload(payload, opts.secret,
                                     opts.algorithm, opts.insecure_check)
                print(ret)
            elif opts.encode:
                ret = encode_payload(payload, opts.secret, opts.algorithm)
                print(ret)
                if opts.test:
                    print(decode_payload(ret, opts.secret, opts.algorithm))
            else:
                logging.error("Unrecognized argument.")
                _parser.print_help()
                sys.exit(1)


if __name__.__eq__("__main__"):
    main()

#END
