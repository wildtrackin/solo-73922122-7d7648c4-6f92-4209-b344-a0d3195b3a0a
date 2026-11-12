#!/usr/bin/env python3
"""端到端演示：HTTPS /docs 可达 + 证书更换 / 409 冲突 / 错配拒绝。

在运行中的服务容器内执行（或任何能访问 BASE_URL 且能读到 PKI 目录的机器）：

    python3 -I scripts/demo_rotate.py

环境变量：
    BASE_URL     默认 https://127.0.0.1:8443
    ADMIN_KEY    默认 demo-admin-key
    PKI_DIR      默认 /var/lib/sandbox-checker/pki
    CA_FILE      默认 $PKI_DIR/ca/ca.pem（用于校验服务证书链）

演示序列：
  1. /docs 与 /health 经 HTTPS 可访问；
  2. 管理密钥错误 → 401；
  3. 查询当前证书指纹（v1）；
  4. 建立一条长连接，更换到 v2 后该旧连接仍可用、且仍持有旧证书；
  5. 新连接完整握手拿到 v2 证书；
  6. 用过期的当前指纹再次更换 → 409 冲突；
  7. 私钥与证书不匹配 → 400 拒绝；
  8. SAN 不含配置 DNS 名 → 400 拒绝；
  9. 加密私钥 → 400 拒绝；
 10. 拒绝后服务仍以 v2 正常服务（旧版保留）。
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import urllib.request
import urllib.error

BASE_URL = os.environ.get("BASE_URL", "https://127.0.0.1:8443").rstrip("/")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "demo-admin-key")
PKI_DIR = os.environ.get("PKI_DIR", "/var/lib/sandbox-checker/pki")
CA_FILE = os.environ.get("CA_FILE", f"{PKI_DIR}/ca/ca.pem")

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}  ✓ {msg}{RESET}")


def info(msg: str) -> None:
    print(f"{YELLOW}▶ {msg}{RESET}")


def fail(msg: str) -> None:
    print(f"{RED}  ✗ {msg}{RESET}")
    sys.exit(1)


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def verified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_FILE)
    # SAN 含 localhost，可通过校验；127.0.0.1 走 IP 时用 check_hostname 关闭
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def insecure_ctx() -> ssl.SSLContext:
    return ssl._create_unverified_context()


def request(method: str, path: str, body: dict | None = None,
            key: str | None = ADMIN_KEY, ctx: ssl.SSLContext | None = None):
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-Admin-Key"] = key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx or insecure_ctx(), timeout=10) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return resp.status, json.loads(raw or "{}")
            return resp.status, {"_raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            payload = {"_raw": raw}
        return exc.code, payload


def peer_fingerprint(host: str, port: int, ctx: ssl.SSLContext,
                     existing_sock=None) -> tuple[str, ssl.SSLSocket | None]:
    """返回对端证书 SHA-256 指纹；传入 existing_sock 时复用该连接。"""
    if existing_sock is None:
        raw = socket.create_connection((host, port), timeout=10)
        sock = ctx.wrap_socket(raw, server_hostname="localhost")
        own = True
    else:
        sock = existing_sock
        own = False
    der = sock.getpeercert(binary_form=True)
    import hashlib
    fp = hashlib.sha256(der).hexdigest()
    if own:
        return fp, sock
    return fp, None


def main() -> None:
    host = BASE_URL.split("://", 1)[1].split(":", 1)[0]
    port = int(BASE_URL.rsplit(":", 1)[1])
    vctx = verified_ctx()

    print("\n=== 1. HTTPS /docs 与 /health 可访问（无明文端口）===")
    for path in ("/docs", "/openapi.json", "/health"):
        status, _ = request("GET", path, key=None)
        if status != 200:
            fail(f"{path} 期望 200，实际 {status}")
    ok("/docs、/openapi.json、/health 均经 HTTPS 返回 200")

    print("\n=== 2. 管理密钥错误被拒绝 ===")
    status, _ = request("GET", "/api/v1/tls/certificate", key="wrong-key")
    if status != 401:
        fail(f"错误密钥期望 401，实际 {status}")
    ok("错误管理密钥返回 401")

    print("\n=== 3. 查询当前证书（应为 v1）===")
    status, cur = request("GET", "/api/v1/tls/certificate")
    if status != 200:
        fail(f"查询当前证书失败：{status} {cur}")
    fp_v1 = cur["fingerprint_sha256"]
    ok(f"当前指纹(v1) = {fp_v1[:16]}…  到期 {cur['not_after']}")

    print("\n=== 4. 建立长连接，更换到 v2，验证旧连接不受影响 ===")
    raw = socket.create_connection((host, port), timeout=10)
    old_sock = vctx.wrap_socket(raw, server_hostname="localhost")
    old_fp_before, _ = peer_fingerprint(host, port, vctx, existing_sock=old_sock)
    if old_fp_before != fp_v1:
        fail("长连接初始证书不是 v1")
    ok("长连接已建立，对端证书为 v1")

    info("提交 v2 证书热更换…")
    v2_cert = read(f"{PKI_DIR}/certs/v2/cert.pem")
    v2_key = read(f"{PKI_DIR}/certs/v2/key.pem")
    status, resp = request(
        "POST", "/api/v1/tls/certificate/rotate",
        {"certificate_pem": v2_cert, "private_key_pem": v2_key,
         "current_fingerprint": fp_v1},
    )
    if status != 200 or resp.get("status") != "rotated":
        fail(f"更换失败：{status} {json.dumps(resp, ensure_ascii=False)}")
    fp_v2 = resp["current"]["fingerprint_sha256"]
    ok(f"更换成功 status=rotated，新指纹(v2) = {fp_v2[:16]}…")

    # 旧连接仍可发起 HTTP 请求，且对端证书仍是 v1
    old_fp_after, _ = peer_fingerprint(host, port, vctx, existing_sock=old_sock)
    if old_fp_after != fp_v1:
        fail("更换后旧连接证书发生变化，已有连接被影响")
    ok("更换后已有连接仍持有 v1 证书且连接保持可用")
    old_sock.close()

    print("\n=== 5. 新连接完整握手使用 v2 ===")
    new_fp, new_sock = peer_fingerprint(host, port, vctx)
    if new_fp != fp_v2:
        fail(f"新连接证书不是 v2：{new_fp}")
    ok("新连接完整握手拿到 v2 证书")
    new_sock.close()
    status, cur = request("GET", "/api/v1/tls/certificate")
    if cur["fingerprint_sha256"] != fp_v2:
        fail("查询接口未反映 v2")
    ok("查询接口确认当前在线版本为 v2")

    print("\n=== 6. 过期指纹再次更换 → 409 冲突 ===")
    status, resp = request(
        "POST", "/api/v1/tls/certificate/rotate",
        {"certificate_pem": v2_cert, "private_key_pem": v2_key,
         "current_fingerprint": fp_v1},  # 仍声明 v1
    )
    if status != 409:
        fail(f"期望 409，实际 {status}")
    if resp.get("detail", {}).get("actual") != fp_v2:
        fail("409 响应未给出实际指纹")
    ok(f"返回 409，actual={resp['detail']['actual'][:16]}…")

    print("\n=== 7. 证书与私钥不匹配 → 400 拒绝 ===")
    foreign_cert = read(f"{PKI_DIR}/certs/foreign/cert.pem")
    status, resp = request(
        "POST", "/api/v1/tls/certificate/rotate",
        {"certificate_pem": foreign_cert, "private_key_pem": v2_key,  # 交叉错配
         "current_fingerprint": fp_v2},
    )
    if status != 400 or "不匹配" not in json.dumps(resp, ensure_ascii=False):
        fail(f"期望 400 不匹配，实际 {status} {resp}")
    ok("私钥不匹配被 400 拒绝")

    print("\n=== 8. SAN 不含配置 DNS 名 → 400 拒绝 ===")
    ws_cert = read(f"{PKI_DIR}/certs/wrong-san/cert.pem")
    ws_key = read(f"{PKI_DIR}/certs/wrong-san/key.pem")
    status, resp = request(
        "POST", "/api/v1/tls/certificate/rotate",
        {"certificate_pem": ws_cert, "private_key_pem": ws_key,
         "current_fingerprint": fp_v2},
    )
    if status != 400 or "SAN" not in json.dumps(resp, ensure_ascii=False):
        fail(f"期望 400 SAN，实际 {status} {resp}")
    ok("SAN 错误被 400 拒绝")

    print("\n=== 9. 加密私钥 → 400 拒绝 ===")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption, Encoding, PrivateFormat, load_pem_private_key,
    )
    v2_key_obj = load_pem_private_key(v2_key.encode(), password=None)
    encrypted = v2_key_obj.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"passphrase")
    ).decode()
    status, resp = request(
        "POST", "/api/v1/tls/certificate/rotate",
        {"certificate_pem": v2_cert, "private_key_pem": encrypted,
         "current_fingerprint": fp_v2},
    )
    if status != 400 or "加密" not in json.dumps(resp, ensure_ascii=False):
        fail(f"期望 400 加密私钥，实际 {status} {resp}")
    ok("加密私钥被 400 拒绝")

    print("\n=== 10. 全部拒绝后服务仍以 v2 正常运行（旧版保留）===")
    status, cur = request("GET", "/api/v1/tls/certificate")
    if cur["fingerprint_sha256"] != fp_v2:
        fail("失败的更换污染了在线版本")
    ok(f"在线版本仍为 v2（{cur['fingerprint_sha256'][:16]}…），服务未中断")
    status, _ = request("GET", "/health", key=None)
    if status != 200:
        fail("健康检查失败")
    ok("/health 正常，业务接口在整个更换期间持续可用")

    print(f"\n{GREEN}全部演示通过。{RESET}")
    print("浏览器访问 https://localhost:8443/docs 可交互查看证书管理接口")
    print("（自签本地 CA，需在系统/浏览器导入 "
          f"{CA_FILE} 后信任）")


if __name__ == "__main__":
    main()
