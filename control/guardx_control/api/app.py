from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..config import get_settings
from .bundles import router as bundles_router
from .detectors import router as detectors_router
from .evidence import router as evidence_router
from .feedback import router as feedback_router
from .policies import proposals_router, router as policies_router, tenants_router
from .profiles import router as profiles_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="GuardX Control API",
        version="0.1.0",
        description="Policy registry, approval workflow, bundle signer.",
    )

    # CORS is opt-in via GUARDX_CORS_ALLOWED_ORIGINS (comma-separated).
    # Empty (prod default) means same-origin only. Dev docker-compose sets it
    # to `http://localhost:5173` so the Vite console can reach the API.
    settings = get_settings()
    origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            allow_headers=["X-GuardX-Key", "Content-Type", "X-Request-ID"],
        )

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    app.include_router(tenants_router)
    app.include_router(policies_router)
    app.include_router(proposals_router)
    app.include_router(bundles_router)
    app.include_router(detectors_router)
    app.include_router(evidence_router)
    app.include_router(feedback_router)
    app.include_router(profiles_router)
    return app


app = create_app()
