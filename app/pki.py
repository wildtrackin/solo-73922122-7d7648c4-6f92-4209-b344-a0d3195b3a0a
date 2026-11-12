"""本地测试用 PKI 生成：一个本地 CA + 两套同域名证书 + 一组错配材料。

仅用于本机 / Compose 演示，**绝不可用于生产**。生成产物：

* ``ca/ca.pem``、``ca/ca-key.pem``      本地根 CA
* ``certs/v1/{cert,key}.pem``           首套服务证书（启动版本）
* ``certs/v2/{cert,key}.pem``           续签版本（同 SAN、不同密钥与序列号）
* ``certs/wrong-san/{cert,key}.pem``    SAN 不含配置 DNS 名（应被拒绝）
* ``certs/foreign/{cert,key}.pem``      另一张同域名证书，与 v1/v2 私钥互不匹配，
                                        用来演示"证书与私钥不匹配"拒绝
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

_DNS_NAMES = ["sandbox.local", "localhost"]


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def _new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _save_key(path: Path, key) -> None:
    _write(
        path,
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        0o600,
    )


def _save_cert(path: Path, cert) -> None:
    _write(path, cert.public_bytes(Encoding.PEM), 0o644)


def _make_ca(out_dir: Path, days: int = 3650):
    key = _new_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sandbox Local Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Sandbox Local Root CA"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    _save_cert(out_dir / "ca" / "ca.pem", cert)
    _save_key(out_dir / "ca" / "ca-key.pem", key)
    return cert, key


def _make_leaf(
    ca_cert,
    ca_key,
    leaf_key,
    dns_names: list[str],
    common_name: str,
    days: int,
):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sandbox Checker Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    return builder.sign(ca_key, hashes.SHA256())


def generate_pki(out_dir: str | os.PathLike[str]) -> dict[str, str]:
    """在 ``out_dir`` 下生成整套演示 PKI，返回各文件绝对路径字典。"""
    out = Path(out_dir)
    ca_cert, ca_key = _make_ca(out)

    result: dict[str, str] = {}

    def emit(name: str, dns_names: list[str], cn: str, days: int = 825) -> None:
        leaf_key = _new_key()
        leaf_cert = _make_leaf(ca_cert, ca_key, leaf_key, dns_names, cn, days)
        cdir = out / "certs" / name
        _save_cert(cdir / "cert.pem", leaf_cert)
        _save_key(cdir / "key.pem", leaf_key)
        result[f"{name}_cert"] = str(cdir / "cert.pem")
        result[f"{name}_key"] = str(cdir / "key.pem")

    # 两套同域名证书（续签：独立密钥、不同序列号）
    emit("v1", _DNS_NAMES, "sandbox.local", days=90)
    emit("v2", _DNS_NAMES, "sandbox.local", days=90)
    # SAN 不含 sandbox.local
    emit("wrong-san", ["other.example"], "other.example", days=90)
    # 同域名但与 v1/v2 不同密钥，用于交叉搭配制造"证书与私钥不匹配"
    emit("foreign", _DNS_NAMES, "sandbox.local", days=90)

    result["ca_cert"] = str(out / "ca" / "ca.pem")
    result["ca_key"] = str(out / "ca" / "ca-key.pem")
    return result


if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(description="生成本地演示 PKI")
    parser.add_argument("out_dir", help="输出目录")
    args = parser.parse_args()
    paths = generate_pki(args.out_dir)
    for k, v in sorted(paths.items()):
        print(f"{k}: {v}")
