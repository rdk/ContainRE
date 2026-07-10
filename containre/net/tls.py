"""TLS interception for the simulated-internet sink (SPEC §7, opt-in `mitm`).

A per-run CA signs on-the-fly leaf certificates for whatever SNI the specimen
requests. If the sandbox trusts the CA (the runner sets SSL_CERT_FILE in the
specimen's environment), the specimen's TLS handshake to our sink succeeds and we
read the *plaintext* HTTPS request. Cert-pinned samples reject our cert and the
handshake fails instead - itself a useful signal.
"""
from __future__ import annotations

import atexit
import datetime
import ipaddress
import re
import shutil
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_DAY = datetime.timedelta(days=1)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _san_for(host: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


class MitmCA:
    # Bound the number of distinct-SNI leaf certs we mint per run: each mint is an
    # RSA-2048 keygen + on-disk PEM, and the SNI is attacker-supplied, so an
    # unbounded cache is a CPU/disk/memory amplification primitive.
    _MAX_CONTEXTS = 128

    def __init__(self, cn: str = "ContainRE MITM CA"):
        self._dir = Path(tempfile.mkdtemp(prefix="containre-mitm-"))
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._default_ctx: ssl.SSLContext | None = None

        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _DAY)
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.key, hashes.SHA256()))
        self._ca_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        # The temp dir holds throwaway leaf private keys; clean it up when the
        # (per-run) process exits so mitm runs don't accumulate /tmp key material.
        atexit.register(self._cleanup)

    def _cleanup(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def close(self) -> None:
        """Remove the temp dir of leaf keys now (also runs at process exit)."""
        atexit.unregister(self._cleanup)
        self._cleanup()

    def ca_pem(self) -> bytes:
        return self._ca_pem

    def write_ca(self, path) -> Path:
        p = Path(path)
        p.write_bytes(self._ca_pem)
        return p

    def _mint(self, host: str) -> Path:
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(host)).issuer_name(self.cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _DAY)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([_san_for(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256()))
        pem = (cert.public_bytes(serialization.Encoding.PEM)
               + leaf_key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.TraditionalOpenSSL,
                                        serialization.NoEncryption()))
        f = self._dir / (re.sub(r"[^A-Za-z0-9._-]", "_", host)[:64] + ".pem")
        f.write_bytes(pem)
        return f

    def _leaf_context(self, host: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.load_cert_chain(str(self._mint(host)))
        return ctx

    def _default_context(self) -> ssl.SSLContext:
        if self._default_ctx is None:
            self._default_ctx = self._leaf_context("localhost")
        return self._default_ctx

    def context_for(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            if len(self._contexts) >= self._MAX_CONTEXTS:
                # Cap reached: reuse a shared default leaf rather than minting an
                # unbounded number of per-SNI keypairs.
                return self._default_context()
            ctx = self._leaf_context(host)
            self._contexts[host] = ctx
            return ctx

    def server_context(self) -> ssl.SSLContext:
        """A TLS server context that swaps in a per-SNI leaf during the handshake.

        This is the top-level listener context (its own leaf, its own SNI
        callback); the per-SNI leaves it dispatches to are capped in context_for.
        """
        ctx = self._leaf_context("localhost")  # default cert when the client sends no SNI

        def _sni(sslsock, server_name, _sslctx):
            if server_name:
                try:
                    sslsock.context = self.context_for(server_name)
                except Exception:
                    pass

        ctx.sni_callback = _sni
        return ctx
