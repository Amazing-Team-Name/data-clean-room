#!/usr/bin/env python3

# Installing `tpm2_tools` (or similar) is required. This can be installed
# from your package manager.
# This script may need sudo permissions to run the `tpm_*` commands.

# Heavily referenced:
# https://gist.github.com/kenplusplus/f025d04047bc044e139d105b4c708d78

import argparse
import hashlib
import logging
import os
import re
import subprocess
import sys
import textwrap

logger = logging.getLogger(__name__)
logging.basicConfig(
    format = "%(levelname)s: %(name)s: %(message)s",
    level = logging.WARN,
)

def check_subprocess_error(res: subprocess.CompletedProcess):
    """
    Logs the error and exits if a non-zero exit code was received.
    Requires `capture_output` to have been `True` (or similar) to
    print stderr.
    """
    if res.returncode != 0:
        logger.fatal("Encountered error:\n" + res.stderr.decode("UTF-8"))
        logger.info("Exiting due to previous error")
        sys.exit(1)

def get_subprocess_result(res: subprocess.CompletedProcess) -> str:
    """
    Logs the results of a completed `subprocess.run` call.
    Requires `capture_output` to have been `True`.
    """
    check_subprocess_error(res)
    return res.stdout.decode("UTF-8")

def tpm2_create_endorsement_key(
    context_path: str = "keys/rsa_ek.ctx",
    pub_path: str = "keys/rsa_ek.pub",
) -> subprocess.CompletedProcess:
    """Creates an endorsement key using the RSA algorithm."""
    result = subprocess.run([
        "tpm2_createek",
        "--ek-context", context_path,
        "--key-algorithm", "rsa",
        "--public", pub_path,
    ], capture_output = True)

    # Check that the files were created successfully
    if (not os.path.exists(context_path)
            or not os.path.exists(pub_path)):
        logger.error(
            "For some reason, either the context or the public key was " +
            "not created while trying to create the endorsement key."
        )

    return result

def tpm2_create_attestation_key(
    ek_context_path: str = "keys/rsa_ek.ctx",
    ak_context_path: str = "keys/rsa_ak.ctx",
    pub_path: str = "keys/rsa_ak.pub",
    priv_path: str = "keys/rsa_ak.priv",
    ak_name_path: str = "keys/rsa_ak.name",
) -> subprocess.CompletedProcess:
    result = subprocess.run([
        "tpm2_createak",
        "--ek-context", ek_context_path,
        "--ak-context", ak_context_path,
        "--key-algorithm", "rsa",
        "--hash-algorithm", "sha256",
        "--signing-algorithm", "rsassa",
        "--public", pub_path,
        "--private", priv_path,
        "--ak-name", ak_name_path,
    ], capture_output = True)
    if (not all(map(os.path.exists, [
            ak_context_path, pub_path, priv_path, ak_name_path,
    ]))):
        logger.error(
            "For some reason, the attestation key files were not " +
            "created."
        )
    return result

def tpm2_read_pcr() -> subprocess.CompletedProcess:
    return subprocess.run(
        ["tpm2_pcrread"],
        capture_output = True,
    )

def tpm2_reset_pcr(slot = 23) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["tpm2_pcrreset", str(slot)],
        capture_output = True,
    )

def tpm2_extend_pcr(sha1: str, sha256: str, slot = 23) -> subprocess.CompletedProcess:
    return subprocess.run([
        "tpm2_pcrextend", f"{slot}:sha1={sha1},sha256={sha256}"
    ], capture_output = True)

def tpm2_create_quote(
    ak_context_path: str = "keys/rsa_ak.ctx",
    plain_path: str = "quotes/pcr_quote.plain",
    sig_path: str = "quotes/pcr_quote.signature",
    pcr_bin_path: str = "quotes/pcr.bin",
    nonce: str = "",
):
    return subprocess.run([
        "tpm2_quote",
        "--key-context", ak_context_path,
        "--pcr-list", "sha1:23+sha256:23",
        "--message", plain_path,
        "--signature", sig_path,
        "--qualification", nonce,
        "--hash-algorithm", "sha256",
        "--pcr", pcr_bin_path,
    ], capture_output = True)

def tpm2_check_quote(
    ak_public_path: str = "keys/rsa_ak.pub",
    plain_path: str = "quotes/pcr_quote.plain",
    sig_path: str = "quotes/pcr_quote.signature",
    pcr_bin_path: str = "quotes/pcr.bin",
    nonce: str = "",
):
    return subprocess.run([
        "tpm2_checkquote",
        "--public", ak_public_path,
        "--message", plain_path,
        "--signature", sig_path,
        "--qualification", nonce,
        "--pcr", pcr_bin_path,
    ], capture_output = True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog = "main.py",
        description = "Use TPM to check integrity of code files",
    )
    subparsers = parser.add_subparsers(dest = "command", required = True)
    gen_parser = subparsers.add_parser("gen", help = "Generate keys")
    quote_parser = subparsers.add_parser("quote", help = "Create a quote")
    quote_parser.add_argument("--nonce", help = "The nonce to use to create the quote")
    quote_parser.add_argument("files", help = "The files to verify", nargs = "+", type = argparse.FileType("r"))
    check_quote_parser = subparsers.add_parser("check_quote", help = "Check a quote")
    check_quote_parser.add_argument("--nonce", help = "The nonce that was used for the quote")
    check_quote_parser.add_argument("--sig", help = "The file with the signature to check against", type = argparse.FileType("r"), required = True)
    args = parser.parse_args()

    logger.debug(f"parser arguments: {args}")

    if args.command == "gen":
        os.makedirs("keys", exist_ok = True)
        logger.debug("Creating endorsement key")
        check_subprocess_error(tpm2_create_endorsement_key())
        logger.debug("Creating attestation keys")
        check_subprocess_error(tpm2_create_attestation_key())
        logger.debug("Success")

    elif args.command == "quote":
        logger.debug("Hashing files")
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()


        # Taken from
        # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
        BUF_SIZE = 65536
        for file in args.files:
            while True:
                data = file.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data.encode("UTF-8"))
                sha1.update(data.encode("UTF-8"))

        hashed_sha256 = sha256.hexdigest()
        hashed_sha1 = sha1.hexdigest()

        logger.debug("Resetting PCR 23")
        check_subprocess_error(tpm2_reset_pcr())

        logger.debug("Extending PCR 23 with hashes")
        check_subprocess_error(tpm2_extend_pcr(hashed_sha1, hashed_sha256))

        # logger.info("Reading PCR")
        # print_subprocess_result(tpm2_read_pcr())

        os.makedirs("quotes", exist_ok = True)

        nonce = ""
        if args.nonce:
            nonce = args.nonce

        logger.debug("Creating quote")
        res = get_subprocess_result(tpm2_create_quote(nonce = nonce))

        maybe_match = re.search(r"sig: (.*)$", res, flags = re.MULTILINE)
        if maybe_match is None:
            logger.fatal("Couldn't find the sig in result:\n{res}")
        else:
            print(maybe_match.group(1))
            logger.info("Success")

    elif args.command == "check_quote":
        nonce = ""
        if args.nonce:
            nonce = args.nonce

        # Get sig
        sig = args.sig.read().strip("\n")

        logger.debug("Checking quotes")
        res = get_subprocess_result(tpm2_check_quote(nonce = nonce))

        maybe_match = re.search(r"sig: (.*)$", res, flags = re.MULTILINE)
        if maybe_match is None:
            logger.fatal("Couldn't find the sig in result:\n{res}")
        elif maybe_match.group(1) != sig:
            logger.fatal("Signature was incorrect.")
            logger.fatal(sig)
            logger.fatal(maybe_match.group(1))
        else:
            logger.info("Success")
