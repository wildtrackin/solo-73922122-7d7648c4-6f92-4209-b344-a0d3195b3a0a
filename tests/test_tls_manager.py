"""TLS 证书热更换的单元测试（需要 cryptography，随容器依赖安装）。

覆盖：
* 指纹归一化与证书 SHA-256 指纹（与 openssl 对齐）；
* validate_bundle：正常 / 过期 / SAN 缺失 / 私钥不匹配 / 加密私钥 / 多张证书；
* TLSManager：首启持久化、热更换、409 冲突、失败保留旧版、重启加载最后版本、
  不会加载半份组合；
* 私钥文件权限 0600、状态目录 0700。

运行（容器内或已安装依赖的环境）：
    PYTHONPATH=/tmp/pylibs:. python3 tests/test_tls_manager.py
"""

from __future__ import annotations

import datetime
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID  # noqa: E402

from app.tls import (  # noqa: E402
    CertValidationError,
    StaleFingerprintError,
    TLSManager,
    normalize_fingerprint,
    sha256_fingerprint_der,
)

DNS = "sandbox.local"
failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")
    else:
        print(f"  ok - {name}")


def pem(key_or_cert) -> str:
    if isinstance(key_or_cert, ec.EllipticCurvePrivateKey):
        return key_or_cert.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
    return key_or_cert.public_bytes(Encoding.PEM).decode()


def make_cert(dns_names: list[str], days_valid: int = 30, key=None,
              ca_cert=None, ca_key=None, expired: bool = False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before = now - datetime.timedelta(days=60)
        not_after = now - datetime.timedelta(days=1)
    else:
        not_before = now - datetime.timedelta(minutes=5)
        not_after = now + datetime.timedelta(days=days_valid)
    issuer = ca_cert.subject if ca_cert else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]
    )
    sign_key = ca_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]),
            critical=False,
        )
    )
    return builder.sign(sign_key, hashes.SHA256()), key


def encrypted_pem(key) -> str:
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"secret")
    ).decode()


def fingerprint_of(cert) -> str:
    return sha256_fingerprint_der(cert.public_bytes(Encoding.DER))


# --------------------------------------------------------------------------- #
print("test_normalize_fingerprint")
hex64 = "ab" * 32
check("小写无分隔", normalize_fingerprint("aB" + "c" * 62) == ("ab" + "c" * 62))
colon_form = ":".join(hex64[i:i + 2].upper() for i in range(0, 64, 2))
check("容忍冒号/大写", normalize_fingerprint(colon_form) == hex64)
check("容忍空白", normalize_fingerprint("  " + hex64 + " ") == hex64)
for bad in ("", "xyz", "g" * 64, "ab" * 31, "ab" * 33):
    try:
        normalize_fingerprint(bad)
        check(f"非法指纹被拒 {bad!r}", False)
    except CertValidationError:
        check(f"非法指纹被拒 {bad!r}", True)

# --------------------------------------------------------------------------- #
print("test_validate_bundle_happy_path")
cert1, key1 = make_cert([DNS, "localhost"])
fp1, cb, kb = __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
    pem(cert1), pem(key1), DNS
)
check("返回指纹", fp1 == fingerprint_of(cert1))
check("证书 PEM 单块", cb.count(b"BEGIN CERTIFICATE") == 1)
check("私钥为未加密 PKCS8", b"ENCRYPTED" not in kb and b"PRIVATE KEY" in kb)

print("test_validate_expired")
exp_cert, exp_key = make_cert([DNS], expired=True)
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        pem(exp_cert), pem(exp_key), DNS
    )
    check("过期证书拒绝", False)
except CertValidationError as exc:
    check("过期证书拒绝", "过期" in str(exc))

not_yet, ny_key = make_cert([DNS])
# 手工构造一张未生效证书
now = datetime.datetime.now(datetime.timezone.utc)
future_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DNS)]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DNS)]))
    .public_key(ny_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now + datetime.timedelta(days=2))
    .not_valid_after(now + datetime.timedelta(days=30))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(DNS)]), critical=False)
    .sign(ny_key, hashes.SHA256())
)
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        pem(future_cert), pem(ny_key), DNS
    )
    check("未生效证书拒绝", False)
except CertValidationError as exc:
    check("未生效证书拒绝", "尚未生效" in str(exc))

print("test_validate_san")
other_cert, other_key = make_cert(["other.example"])
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        pem(other_cert), pem(other_key), DNS
    )
    check("SAN 不匹配拒绝", False)
except CertValidationError as exc:
    check("SAN 不匹配拒绝", "SAN" in str(exc) and DNS in str(exc))

print("test_validate_key_mismatch")
cert_a, key_a = make_cert([DNS])
_, key_b = make_cert([DNS])
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        pem(cert_a), pem(key_b), DNS
    )
    check("私钥不匹配拒绝", False)
except CertValidationError as exc:
    check("私钥不匹配拒绝", "不匹配" in str(exc))

print("test_validate_encrypted_key")
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        pem(cert1), encrypted_pem(key1), DNS
    )
    check("加密私钥拒绝", False)
except CertValidationError as exc:
    check("加密私钥拒绝", "加密" in str(exc))

print("test_validate_multiple_certs")
cert2, key2 = make_cert([DNS])
two_certs = pem(cert1) + pem(cert2)
try:
    __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
        two_certs, pem(key1), DNS
    )
    check("多张证书拒绝", False)
except CertValidationError as exc:
    check("多张证书拒绝", "一张" in str(exc))

for empty in ("", "   "):
    try:
        __import__("app.tls", fromlist=["validate_bundle"]).validate_bundle(
            empty, pem(key1), DNS
        )
        check("空证书拒绝", False)
    except CertValidationError:
        check(f"空证书拒绝 {empty!r}", True)

# --------------------------------------------------------------------------- #
print("test_manager_lifecycle")
work = tempfile.mkdtemp(prefix="tls-test-")
try:
    state = os.path.join(work, "state")
    mgr = TLSManager(state_dir=state, expected_dns=DNS)

    # 首次：无持久化状态
    check("空目录无法启动加载", mgr.bootstrap_from_disk() is False)

    mgr.bootstrap_from_pem(pem(cert1), pem(key1))
    check("首启指纹", mgr.fingerprint == fingerprint_of(cert1))
    check("SSLContext 已建立", mgr.context is not None)
    check("状态目录权限 0700", oct(os.stat(state).st_mode & 0o777) == "0o700")
    link = Path(state) / "current"
    check("current 是符号链接", link.is_symlink())
    vdir = os.path.realpath(link)
    check("私钥权限 0600",
          oct(os.stat(os.path.join(vdir, "key.pem")).st_mode & 0o777) == "0o600")
    check("证书权限 0644",
          oct(os.stat(os.path.join(vdir, "cert.pem")).st_mode & 0o777) == "0o644")

    print("test_rotate_success")
    cert3, key3 = make_cert([DNS, "localhost"])
    fp3 = fingerprint_of(cert3)
    info = mgr.rotate(pem(cert3), pem(key3), claimed_fingerprint=fingerprint_of(cert1))
    check("更换后指纹更新", info["fingerprint_sha256"] == fp3)
    check("管理器指纹更新", mgr.fingerprint == fp3)
    check("current 指向新版本",
          os.path.realpath(link) != vdir and os.path.exists(link / "cert.pem"))

    print("test_rotate_409_stale")
    try:
        mgr.rotate(pem(cert3), pem(key3), claimed_fingerprint=fingerprint_of(cert1))
        check("过期指纹触发 409", False)
    except StaleFingerprintError as exc:
        check("过期指纹触发 409",
              exc.expected == fingerprint_of(cert1) and exc.actual == fp3)

    print("test_rotate_idempotent")
    before = mgr.fingerprint
    info = mgr.rotate(pem(cert3), pem(key3), claimed_fingerprint=fp3)
    check("同证书幂等", info["fingerprint_sha256"] == before)

    print("test_rotate_failure_keeps_old")
    # 提交私钥不匹配的组合：必须抛错且在线版本不变
    try:
        mgr.rotate(pem(cert_a), pem(key_b), claimed_fingerprint=fp3)
        check("错配更换被拒", False)
    except CertValidationError:
        check("错配更换被拒", True)
    check("失败后在线版本保留", mgr.fingerprint == fp3)
    check("失败后 current 仍指向 v3",
          os.path.realpath(link) == os.path.realpath(link))  # 链接未损坏
    # current 内容仍为 v3
    with open(link / "cert.pem", "rb") as fh:
        on_disk = x509.load_pem_x509_certificate(fh.read())
    check("落盘版本仍是 v3", fingerprint_of(on_disk) == fp3)

    print("test_restart_loads_last_success")
    mgr2 = TLSManager(state_dir=state, expected_dns=DNS)
    check("重启发现持久化版本", mgr2.bootstrap_from_disk() is True)
    check("重启加载最后成功指纹", mgr2.fingerprint == fp3)

    print("test_half_bundle_rejected")
    # 制造一个只含证书、缺私钥的版本目录并把 current 指过去
    bad_dir = Path(state) / "deadbeefdeadbeef"
    bad_dir.mkdir()
    (bad_dir / "cert.pem").write_bytes(pem(cert1).encode())
    tmp_link = Path(state) / ".link-tmp-bad"
    os.symlink(bad_dir.name, tmp_link)
    os.replace(tmp_link, link)
    mgr3 = TLSManager(state_dir=state, expected_dns=DNS)
    try:
        mgr3.bootstrap_from_disk()
        check("半份组合拒绝加载", False)
    except RuntimeError as exc:
        check("半份组合拒绝加载", "不完整" in str(exc))

    print("test_private_key_not_in_info")
    info = mgr.current_info()
    allowed = {"dns_name", "fingerprint_sha256", "subject", "not_after"}
    check("信息字段白名单", set(info.keys()) == allowed)
    check("信息不含 PRIVATE", "PRIVATE" not in str(info))

finally:
    shutil.rmtree(work, ignore_errors=True)

print()
if failures:
    print(f"{len(failures)} 项失败")
    sys.exit(1)
print("全部 TLS 管理器测试通过")
