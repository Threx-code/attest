"""URL routing, offered as a mountable set rather than imposed.

Nothing here is wired automatically. A host includes it where it wants it, or writes
its own routes against the same viewsets — this file is a convenience, and mounting it
is a deliberate act.
"""

from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from attest.adapters.django.views import AttestationViewSet, PendingActionViewSet

__all__ = ["ROUTER", "app_name", "urlpatterns"]

app_name = "attest"

ROUTER = DefaultRouter()
ROUTER.register("attestations", AttestationViewSet, basename="attestation")
ROUTER.register("pending-actions", PendingActionViewSet, basename="pending-action")

urlpatterns = [path("", include(ROUTER.urls))]
