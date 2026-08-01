"""The Django application definition.

The label is ``attest`` rather than the package's last path component. Django defaults
the label to the final segment, which here would be ``django`` — an app labelled
``django`` in ``INSTALLED_APPS`` is confusing at best, and collides the moment another
package does the same.
"""

from __future__ import annotations

from django.apps import AppConfig

__all__ = ["AttestAppConfig"]


class AttestAppConfig(AppConfig):
    """Registers the reference models and their append-only migrations."""

    name = "attest.adapters.django"
    label = "attest"
    verbose_name = "Attest control plane"
    default_auto_field = "django.db.models.BigAutoField"
