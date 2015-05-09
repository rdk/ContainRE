from .local import LocalRuntime

__all__ = ["LocalRuntime", "DockerRuntime", "docker_available"]


def __getattr__(name):
    # Import DockerRuntime lazily so `import containre.runtime` never requires docker.
    if name in ("DockerRuntime", "docker_available"):
        from . import docker
        return getattr(docker, name)
    raise AttributeError(name)
