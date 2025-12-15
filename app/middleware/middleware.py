"""
中间件配置模块，负责设置和配置应用程序的中间件
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse # 引入 JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# from app.middleware.request_logging_middleware import RequestLoggingMiddleware
from app.middleware.smart_routing_middleware import SmartRoutingMiddleware
from app.core.constants import API_VERSION
from app.core.security import verify_auth_token
from app.log.logger import get_middleware_logger

logger = get_middleware_logger()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    认证中间件，处理未经身份验证的请求
    """

    async def dispatch(self, request: Request, call_next):
        """很怀疑被判断为是钓鱼网站就是因为对于其他的路径返回了307的状态码回到主页"""
        path = request.url.path.lower()

        # --- [新增] 1. 安全拦截：直接阻断恶意扫描 ---
        # 只要包含这些后缀或路径，直接返回 404 Not Found。
        # 这会让扫描器认为你的服务器上根本没有这些东西。
        suspicious_extensions = (
            '.php', '.jsp', '.asp', '.aspx', '.exe', '.sh',
            '.sql', '.env', '.git', '.config', '.yaml', '.yml',
            '/wp-admin', '/wp-login', '/owa', '/autodiscover','.htaccess'
        )
        if path.endswith(suspicious_extensions) or any(ext in path for ext in ['.git/', '/.env']):
            logger.warning(f"Blocked malicious scan: {path} from {request.client.host}")
            return Response(status_code=404)  # 直接返回 404，不解释

        # --- 白名单逻辑 ---
        # 这些路径不需要认证
        allowed_prefixes = [
            "/auth",
            "/static",
            "/gemini",
            "/v1",
            f"/{API_VERSION}",
            "/health",
            "/hf",
            "/openai",
            "/api/version/check",
            "/vertex-express",
            "/upload"
        ]

        # 如果是根路径 "/"，也不需要在这里拦截，交给路由处理（通常根路径是登录页）
        if path == "/" or any(path.startswith(prefix) for prefix in allowed_prefixes):
            return await call_next(request)

        # --- 认证检查 ---
        auth_token = request.cookies.get("auth_token")
        if not auth_token or not verify_auth_token(auth_token):
            logger.warning(f"Unauthorized access attempt to {path}")

            # --- [修改] 2. 智能拒绝 ---
            # 只有当请求看起来像是浏览器访问页面时，才跳转到登录页。
            # 其他情况（API调用、未知资源）返回 403 或 404。
            accept_header = request.headers.get("accept", "")

            if "text/html" in accept_header:
                # 浏览器请求网页 -> 跳转登录
                return RedirectResponse(url="/")
            else:
                # API 请求或机器扫描 -> 返回 404 或 403
                # 建议返回 404，隐藏服务器细节
                return JSONResponse(
                    status_code=404,
                    content={"detail": "Not Found"}
                )

        response = await call_next(request)
        return response

def setup_middlewares(app: FastAPI) -> None:
    """
    设置应用程序的中间件

    Args:
        app: FastAPI应用程序实例
    """
    # 添加智能路由中间件（必须在认证中间件之前）
    app.add_middleware(SmartRoutingMiddleware)

    # 添加认证中间件
    app.add_middleware(AuthMiddleware)

    # 添加请求日志中间件（可选，默认注释掉）
    # app.add_middleware(RequestLoggingMiddleware)

    # 配置CORS中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=[
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS",
        ],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=600,
    )
