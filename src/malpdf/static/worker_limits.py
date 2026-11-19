import os

from malpdf.static.execution import is_vm


def apply_code_limits(limits):
    import resource

    if os.getpgrp() != os.getpid():
        os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    if not is_vm(limits):
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    return {"address_space_bytes": list(resource.getrlimit(resource.RLIMIT_AS)),
            "cpu_seconds": list(resource.getrlimit(resource.RLIMIT_CPU)),
            "wall_seconds": limits.wall_seconds, "disposable_process_group": os.getpgrp() == os.getpid()}
