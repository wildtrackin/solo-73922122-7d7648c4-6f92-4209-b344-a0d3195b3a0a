"""FastAPI 应用：systemd 沙箱策略离线核查 + TLS 证书热更换。

所有计算均在本地完成，不发起任何外部网络请求，适合离线维护终端部署。
业务与管理接口都只在 HTTPS 上暴露（明文端口不对外）；证书管理接口通过
启动配置的管理密钥（``X-Admin-Key`` 头，恒定时间比较）鉴权。
"""

from __future__ import annotations

import hmac
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse

from . import __version__
from .engine import PolicyError, evaluate
from .schemas import (
    CertInfo,
    CertRotateRequest,
    CertRotateResponse,
    EvaluateRequest,
    EvaluateResponse,
)
from .tls import (
    CertValidationError,
    StaleFingerprintError,
    TLSManager,
    normalize_fingerprint,
)

app = FastAPI(
    title="systemd 沙箱策略核查 API",
    version=__version__,
    description=(
        "离线核对 systemd 沙箱指令（ProtectSystem / ProtectHome / ReadWritePaths / "
        "InaccessiblePaths / PrivateTmp）是否会阻断守护进程的真实文件操作。"
        "提交 unit 策略 JSON 与按时间排列的进程审计事件，返回首个失败原因、"
        "完整判定轨迹与命中的策略项，辅助维护人员修改 unit。\n\n"
        "另提供经管理密钥保护的 TLS 证书热更换接口：更换期间已有连接不受影响，"
        "新连接的完整握手使用新版证书；私钥不会出现在任何响应或日志中。"
    ),
)

# 由 server 启动入口注入；模块级单例，单进程内共享
_tls_manager: Optional[TLSManager] = None
_admin_key: Optional[str] = os.environ.get("ADMIN_KEY")


def configure(tls_manager: TLSManager, admin_key: str) -> None:
    """由启动入口注入 TLS 管理器与管理密钥。"""
    global _tls_manager, _admin_key
    _tls_manager = tls_manager
    _admin_key = admin_key


def get_tls_manager() -> TLSManager:
    if _tls_manager is None:
        raise HTTPException(status_code=503, detail="TLS 子系统尚未初始化")
    return _tls_manager


def require_admin_key(x_admin_key: Optional[str] = Header(default=None)) -> None:
    """管理接口鉴权：恒定时间比较，避免时序侧信道。"""
    if not _admin_key:
        # 未配置管理密钥时一律拒绝（fail-closed）
        raise HTTPException(status_code=503, detail="管理密钥未配置，管理接口不可用")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, _admin_key):
        raise HTTPException(status_code=401, detail="管理密钥缺失或错误")


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"], summary="健康检查")
def health() -> dict:
    return {"status": "ok", "service": "systemd-sandbox-checker", "version": __version__}


@app.post(
    "/api/v1/evaluate",
    response_model=EvaluateResponse,
    tags=["evaluate"],
    summary="回放审计事件并核对沙箱策略",
    responses={
        422: {"description": "策略或事件字段不合法（含相对路径出现在策略中等）"},
    },
)
def evaluate_events(req: EvaluateRequest) -> EvaluateResponse:
    """按进程继承与路径规范化逐步判定；拒绝路径优先于可写路径。"""
    try:
        result = evaluate(
            req.policy.model_dump(by_alias=False, exclude_none=False),
            [e.to_engine() for e in req.events],
        )
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return EvaluateResponse(**result)


# --------------------------------------------------------------------------- #
# 证书管理（需管理密钥）
# --------------------------------------------------------------------------- #
@app.get(
    "/api/v1/tls/certificate",
    response_model=CertInfo,
    tags=["tls"],
    summary="查询当前证书信息（不含私钥）",
    dependencies=[Depends(require_admin_key)],
    responses={401: {"description": "管理密钥缺失或错误"}},
)
def get_certificate(manager: TLSManager = Depends(get_tls_manager)) -> CertInfo:
    return CertInfo(**manager.current_info())


@app.post(
    "/api/v1/tls/certificate/rotate",
    response_model=CertRotateResponse,
    tags=["tls"],
    summary="校验并热更换 TLS 证书（已有连接不受影响）",
    dependencies=[Depends(require_admin_key)],
    responses={
        400: {"description": "证书/私钥校验失败（有效期、SAN、密钥匹配、加密私钥等）"},
        401: {"description": "管理密钥缺失或错误"},
        409: {"description": "提交的当前指纹与服务实际指纹不一致（已被其他更换改变）"},
    },
)
def rotate_certificate(
    req: CertRotateRequest,
    manager: TLSManager = Depends(get_tls_manager),
) -> CertRotateResponse:
    """原子更换证书：

    1. 先做乐观并发检查（current_fingerprint 与当前不一致 → 409）；
    2. 在内存中完整校验证书（有效期、SAN 含配置 DNS 名、与未加密私钥匹配）；
    3. 整份持久化并在同一 SSLContext 上热加载——旧连接继续走旧证书，
       之后新连接的完整握手使用新证书；任一步失败保留旧版。
    """
    # 指纹格式先校验，给出明确 400
    try:
        normalize_fingerprint(req.current_fingerprint)
    except CertValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    previous = manager.fingerprint
    try:
        info = manager.rotate(
            cert_pem=req.certificate_pem,
            key_pem=req.private_key_pem,
            claimed_fingerprint=req.current_fingerprint,
        )
    except StaleFingerprintError as exc:
        # 不回显任何证书/私钥内容，仅给出双方指纹
        raise HTTPException(
            status_code=409,
            detail={
                "error": "current_fingerprint 与服务当前证书不一致",
                "submitted": exc.expected,
                "actual": exc.actual,
            },
        ) from exc
    except CertValidationError as exc:
        # 错误信息只包含校验结论，绝不包含私钥内容
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    status = "unchanged" if info["fingerprint_sha256"] == previous else "rotated"
    return CertRotateResponse(
        status=status,
        previous_fingerprint=previous,
        current=CertInfo(**info),
    )
