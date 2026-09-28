FROM mcr.microsoft.com/devcontainers/python:1-3.11-bullseye

# Keep the image generic: project dependencies are resolved from pyproject.toml
# by devcontainer.json rather than being installed as unmanaged global packages.
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

USER vscode
