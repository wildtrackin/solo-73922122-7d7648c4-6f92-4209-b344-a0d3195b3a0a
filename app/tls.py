"""TLS 证书热更换与持久化。

设计要点（对应运维需求）：

* 单进程内持有一个可变的 :class:`ssl.SSLContext`；更换证书时对同一上下文
  再次 ``load_cert_chain``，**已建立的连接不受影响**，之后新连接的完整握手
  会使用新证书（同时关闭会话票据与会话缓存，确保演示时新连接必定完整握手）。
* 提交的证书与私钥先在内存中完成全部校验（有效期 / SAN / 与私钥匹配 /
  未加密私钥 / 单张 PEM 证书），校验期间服务完全正常。
* 校验通过后以"版本目录 + 原子符号链接切换"整份持久化：链接只会指向完整
  落盘的证书+私钥组合，进程崩溃也不会出现半份组合；重启时加载最后成功版本。
* 私钥以 0600 权限保存，且从不写入日志、不出现在任何响应中。

第三方依赖 ``cryptography`` 仅在函数内部导入，使本模块中不涉及 x509 的纯
逻辑（指纹规范化等）在没有安装依赖的离线环境里也能被测试脚本导入。
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import ssl
import tempfile
import threading
from pathlib import Path
from typing import Optional

# 指纹以小写无冒号 hex 对外，同时容忍冒号/空白/大写输入
_CERT_FILE = "cert.pem"
_KEY_FILE = "key.pem"
_LINK_NAME = "current"


class CertValidationError(ValueError):
    """证书或私钥校验失败（映射为 HTTP 400）。"""


class StaleFingerprintError(Exception):
    """提交携带的当前指纹与服务实际当前指纹不一致（映射为 HTTP 409）。"""

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"当前证书指纹已变化：提交者声明 {expected}，服务实际为 {actual}"
        )
        self.expected = expected
        self.actual = actual


def normalize_fingerprint(value: str) -> str:
    """把任意常见写法的 SHA-256 指纹归一为小写无分隔 hex。"""
    if not isinstance(value, str):
        raise CertValidationError("指纹必须是字符串")
    cleaned = value.strip().replace(":", "").replace(" ", "").lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise CertValidationError("current_fingerprint 必须是 64 位十六进制 SHA-256 指纹")
    return cleaned


def sha256_fingerprint_der(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


def _fingerprint_of_pem_file(cert_path: str) -> str:
    """读取 PEM 证书文件并计算其 SHA-256 指纹。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    return sha256_fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


# --------------------------------------------------------------------------- #
# 纯 cryptography 校验（无 I/O、无副作用）
# --------------------------------------------------------------------------- #
def _load_x509(cert_pem: str, key_pem: str):
    """解析并校验单张 PEM 证书与未加密私钥，返回 (cert_obj, key_obj)。"""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        load_pem_private_key,
    )

    if not isinstance(cert_pem, str) or not cert_pem.strip():
        raise CertValidationError("certificate_pem 不能为空")
    if not isinstance(key_pem, str) or not key_pem.strip():
        raise CertValidationError("private_key_pem 不能为空")

    cert_bytes = cert_pem.encode("utf-8")
    key_bytes = key_pem.encode("utf-8")

    # --- 单张证书：禁止一次提交多张 ---------------------------------------
    cert_marker = b"-----BEGIN CERTIFICATE-----"
    if cert_bytes.count(cert_marker) != 1:
        raise CertValidationError(
            "certificate_pem 必须且只能包含一张 PEM 证书"
        )
    if b"-----BEGIN " not in key_bytes:
        raise CertValidationError("private_key_pem 不是合法的 PEM 私钥")

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError as exc:
        raise CertValidationError(f"证书解析失败：{exc}") from exc

    # --- 私钥必须未加密 ---------------------------------------------------
    # 加密的 PKCS#8 PEM 头部为 ENCRYPTED PRIVATE KEY；传统 PEM 加密则带
    # Proc-Type: 4,ENCRYPTED。两种都拒绝。
    if b"ENCRYPTED PRIVATE KEY" in key_bytes or b"ENCRYPTED" in key_bytes:
        raise CertValidationError("私钥必须是未加密的 PEM 私钥，拒绝加密私钥")
    try:
        key = load_pem_private_key(key_bytes, password=None)
    except TypeError as exc:
        raise CertValidationError("私钥受密码保护，必须提交未加密私钥") from exc
    except ValueError as exc:
        raise CertValidationError(f"私钥解析失败：{exc}") from exc

    # 重新序列化确认拿到的是私钥对象（load_pem_private_key 已保证），并确认
    # 该密钥对象可无密码导出（未加密）。
    try:
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    except Exception as exc:  # pragma: no cover - 理论上不会发生
        raise CertValidationError(f"私钥不可用：{exc}") from exc

    return cert, key


def _check_validity(cert) -> None:
    import datetime

    try:
        # cryptography >= 42
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - 老版本 cryptography
        now = datetime.datetime.utcnow()
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

    if now < not_before:
        raise CertValidationError(
            f"证书尚未生效（not_before={not_before.isoformat()}）"
        )
    if now > not_after:
        raise CertValidationError(
            f"证书已过期（not_after={not_after.isoformat()}）"
        )


def _check_san(cert, expected_dns: str) -> None:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound as exc:
        raise CertValidationError("证书缺少 SAN（subjectAltName）扩展") from exc

    names = ext.value.get_values_for_type(x509.DNSName)
    if expected_dns not in names:
        raise CertValidationError(
            f"证书 SAN 不包含配置的 DNS 名 {expected_dns!r}；实际 SAN={names}"
        )


def _check_key_matches(cert, key) -> None:
    cert_pub = cert.public_key()
    key_pub = key.public_key()
    try:
        same = cert_pub.public_numbers() == key_pub.public_numbers()
    except Exception as exc:
        raise CertValidationError(f"证书与私钥类型无法比对：{exc}") from exc
    if not same:
        raise CertValidationError("证书与私钥不匹配（公钥不一致）")


def validate_bundle(
    cert_pem: str,
    key_pem: str,
    expected_dns: str,
) -> tuple[str, bytes, bytes]:
    """完整校验提交内容，返回 (sha256 指纹, 证书 PEM bytes, 私钥 PEM bytes)。

    校验顺序：解析 → 未加密私钥 → 有效期 → SAN → 与私钥匹配。
    任何一步失败都抛 :class:`CertValidationError`，且不产生任何副作用。
    """
    cert, key = _load_x509(cert_pem, key_pem)
    _check_validity(cert)
    _check_san(cert, expected_dns)
    _check_key_matches(cert, key)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = sha256_fingerprint_der(der)
    # 统一以规范 PEM 字节落盘（证书保持原始 PEM，私钥转成未加密 PKCS#8）
    cert_bytes = cert.public_bytes(Encoding.PEM)
    key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return fingerprint, cert_bytes, key_bytes


# --------------------------------------------------------------------------- #
# 持久化与热切换
# --------------------------------------------------------------------------- #
class TLSManager:
    """持有 SSLContext、当前指纹并负责整份持久化与原子切换。"""

    def __init__(self, state_dir: str | os.PathLike[str], expected_dns: str) -> None:
        self.state_dir = Path(state_dir)
        self.expected_dns = expected_dns
        self._lock = threading.Lock()
        self._ctx: Optional[ssl.SSLContext] = None
        self._fingerprint: Optional[str] = None
        self._subject: Optional[str] = None
        self._not_after: Optional[str] = None

    # ---------------- 元数据（响应里只放非敏感信息） -------------------- #
    @property
    def fingerprint(self) -> Optional[str]:
        with self._lock:
            return self._fingerprint

    def current_info(self) -> dict:
        with self._lock:
            return {
                "dns_name": self.expected_dns,
                "fingerprint_sha256": self._fingerprint,
                "subject": self._subject,
                "not_after": self._not_after,
            }

    @property
    def context(self) -> ssl.SSLContext:
        if self._ctx is None:
            raise RuntimeError("TLS 尚未初始化")
        return self._ctx

    # ---------------- 持久化原语 ---------------------------------------- #
    def _current_link(self) -> Path:
        return self.state_dir / _LINK_NAME

    def _persist_atomic(self, cert_bytes: bytes, key_bytes: bytes) -> None:
        """写入新版本目录并原子切换 current 符号链接。

        新版本目录完整 fsync 后才切换链接；切换使用 rename 原子替换，
        因此 current 永远只指向完整的证书+私钥组合，不存在半份状态。
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.state_dir, 0o700)
        except PermissionError:  # pragma: no cover - 非属主时忽略
            pass

        # 用完整 SHA-256 指纹作为版本目录名：天然去重且无碰撞风险
        version = hashlib.sha256(cert_bytes).hexdigest()
        version_dir = self.state_dir / version
        if version_dir.exists():
            # 同名版本理论上即同一张证书；校验内容一致后直接复用，避免把
            # 不同内容写进同一目录。完整 64 位指纹碰撞概率可忽略。
            if (version_dir / _CERT_FILE).read_bytes() != cert_bytes:
                raise CertValidationError("内部错误：证书指纹冲突，拒绝覆盖已有版本")
            return
        version_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(version_dir, 0o700)
        except PermissionError:  # pragma: no cover - 非属主时忽略
            pass

        cert_path = version_dir / _CERT_FILE
        key_path = version_dir / _KEY_FILE
        _atomic_write(cert_path, cert_bytes, mode=0o644)
        _atomic_write(key_path, key_bytes, mode=0o600)

        link = self._current_link()
        tmp_link = self.state_dir / (".link-tmp-" + os.urandom(4).hex())
        os.symlink(version_dir.name, tmp_link)
        os.replace(tmp_link, link)  # 原子替换
        _fsync_dir(self.state_dir)

    def _load_last_success(self) -> tuple[str, str]:
        """从 current 链接加载最后成功版本，缺失或损坏时抛异常。"""
        link = self._current_link()
        if not link.exists():
            raise FileNotFoundError(f"未找到已持久化的证书链接：{link}")
        cert_path = link / _CERT_FILE
        key_path = link / _KEY_FILE
        # 符号链接可能指向不完整目录，整份校验，任一缺失即失败
        if not cert_path.is_file() or not key_path.is_file():
            raise RuntimeError("持久化的证书组合不完整，拒绝加载半份组合")
        return str(cert_path), str(key_path)

    # ---------------- 启动加载 ------------------------------------------ #
    def bootstrap_from_disk(self) -> bool:
        """启动时加载最后成功版本；无持久化证书时返回 False。"""
        with self._lock:
            try:
                cert_path, key_path = self._load_last_success()
            except FileNotFoundError:
                return False
            self._ctx = _build_context()
            self._ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self._refresh_metadata_from_files(cert_path)
            # 从落盘证书重新计算指纹，保证重启后乐观并发检查可用
            self._fingerprint = _fingerprint_of_pem_file(cert_path)
            return True

    def bootstrap_from_pem(self, cert_pem: str, key_pem: str) -> None:
        """首次启动（无持久化状态）时用启动证书初始化，并立即持久化。"""
        fingerprint, cert_bytes, key_bytes = validate_bundle(
            cert_pem, key_pem, self.expected_dns
        )
        with self._lock:
            self._persist_atomic(cert_bytes, key_bytes)
            cert_path, key_path = self._load_last_success()
            self._ctx = _build_context()
            self._ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self._fingerprint = fingerprint
            self._refresh_metadata_from_files(cert_path)

    # ---------------- 热更换 -------------------------------------------- #
    def rotate(
        self,
        cert_pem: str,
        key_pem: str,
        claimed_fingerprint: str,
    ) -> dict:
        """校验并原子更换证书。

        * 指纹先于任何重活做乐观并发检查，不匹配抛 409；
        * 全部校验在锁外完成，校验期间已有服务与连接完全不受影响；
        * 仅在持久化 + load_cert_chain 全部成功后才更新当前指纹；
          任何一步失败都保留旧版（旧 context 不动）。
        """
        claimed = normalize_fingerprint(claimed_fingerprint)

        # 完整内存校验（无锁、无 I/O，不触碰在线 context）
        fingerprint, cert_bytes, key_bytes = validate_bundle(
            cert_pem, key_pem, self.expected_dns
        )

        with self._lock:
            if self._fingerprint is None:
                raise RuntimeError("TLS 尚未初始化，无法更换")
            if claimed != self._fingerprint:
                raise StaleFingerprintError(
                    expected=claimed, actual=self._fingerprint
                )
            if fingerprint == self._fingerprint:
                # 同一张证书重复提交：幂等成功，无需重写（锁内直接构造，勿重入）
                return {
                    "dns_name": self.expected_dns,
                    "fingerprint_sha256": self._fingerprint,
                    "subject": self._subject,
                    "not_after": self._not_after,
                }

            # 1) 先在临时 context 上验证新组合确实能被 OpenSSL 加载，
            #    避免污染在线 context（失败时旧连接继续可用）。
            probe = _build_context()
            try:
                with _temp_chain(self.state_dir, cert_bytes, key_bytes) as (c, k):
                    probe.load_cert_chain(certfile=c, keyfile=k)
            except ssl.SSLError as exc:
                raise CertValidationError(f"新证书组合无法加载：{exc}") from exc

            # 2) 整份持久化 + 原子切换链接
            self._persist_atomic(cert_bytes, key_bytes)
            cert_path, key_path = self._load_last_success()

            # 3) 在在线 context 上热加载；已有连接不受影响，新连接用新版
            try:
                assert self._ctx is not None
                self._ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            except ssl.SSLError as exc:  # pragma: no cover - 探针已先行验证
                # 在线加载失败：持久化已切换但内存仍是旧版，进程不重启时旧版
                # 继续服务；重启会加载新落盘版本（其已通过探针，必然可加载）。
                raise CertValidationError(f"在线切换失败，保留当前版本：{exc}") from exc

            self._fingerprint = fingerprint
            self._refresh_metadata_from_bytes(cert_bytes)
            # 注意：此处已持有 _lock，不能再调用会重复加锁的 current_info()
            return {
                "dns_name": self.expected_dns,
                "fingerprint_sha256": self._fingerprint,
                "subject": self._subject,
                "not_after": self._not_after,
            }

    # ---------------- 元数据填充 ---------------------------------------- #
    def _refresh_metadata_from_files(self, cert_path: str) -> None:
        with open(cert_path, "rb") as fh:
            self._refresh_metadata_from_bytes(fh.read())

    def _refresh_metadata_from_bytes(self, cert_bytes: bytes) -> None:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_bytes)
        try:
            self._not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:  # pragma: no cover
            self._not_after = cert.not_valid_after.isoformat()
        # subject 可能为空，做健壮处理
        try:
            self._subject = cert.subject.rfc4514_string()
        except Exception:  # pragma: no cover
            self._subject = ""


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _build_context() -> ssl.SSLContext:
    """构造服务端 TLS 上下文。

    关闭会话票据与会话缓存，使每次新连接都走完整 TLS 握手，从而在更换
    证书后新连接必然拿到新证书（也让演示结果确定可复现）。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    # 让服务端在重协商/握手时优先选用自身策略
    ctx.post_handshake_auth = False
    try:
        # OpenSSL 1.1.1+：关闭会话票据
        ctx.options |= _option_no_ticket()
    except (ValueError, AttributeError):  # pragma: no cover
        pass
    try:
        ctx.num_tickets = 0  # type: ignore[attr-defined]
    except (AttributeError, ValueError, NotImplementedError):  # pragma: no cover
        pass
    # 关闭服务端会话缓存（stateless 之外的会话复用路径）
    try:
        ctx.set_session_cache_size(0)
    except (AttributeError, NotImplementedError):  # pragma: no cover
        pass
    return ctx


def _option_no_ticket() -> int:
    # ssl.OP_NO_TICKET 在 3.11 可用；老版本回退到 OpenSSL 常量值
    return getattr(ssl, "OP_NO_TICKET", 0x00004000)


@contextlib.contextmanager
def _temp_chain(
    base_dir: Path, cert_bytes: bytes, key_bytes: bytes
):
    """把待验证的证书/私钥写入仅属主可访问的临时文件，退出即删除。"""
    base_dir.mkdir(parents=True, exist_ok=True)
    fd_c, c_path = tempfile.mkstemp(prefix=".probe-cert-", dir=base_dir)
    fd_k, k_path = tempfile.mkstemp(prefix=".probe-key-", dir=base_dir)
    try:
        with os.fdopen(fd_c, "wb") as fh:
            fh.write(cert_bytes)
        with os.fdopen(fd_k, "wb") as fh:
            fh.write(key_bytes)
        os.chmod(c_path, 0o600)
        os.chmod(k_path, 0o600)
        yield c_path, k_path
    finally:
        for p in (c_path, k_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_name(path.name + ".tmp-" + os.urandom(4).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)
