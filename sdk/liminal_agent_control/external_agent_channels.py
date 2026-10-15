"""Inspect the enumerated Docker channels of the fixed owned-agent profile.

This is a read-only admission check on a trusted raw ``docker inspect`` object,
not a generic escape detector. Exact image, argv, environment, source and
resource binding remain the supervisor's responsibility. A public projection
preserves the checked values without publishing host paths or daemon metadata.

Docker's API models distinguish required fields from ``omitempty`` fields:
https://pkg.go.dev/github.com/moby/moby/api/types/container
https://docs.docker.com/reference/cli/dockerd/
This profile requires explicit private IPC/cgroup namespaces and the standard
runc runtime. Daemons using other defaults need a separately reviewed profile;
an absent load-bearing inspect field is never treated as a safe default.
"""
from __future__ import annotations

import json
import posixpath
from typing import Any

from .authority import ControlError, canonical_bytes, digest

CHANNELS_SCHEMA = "liminal-owned-agent-docker-channels-v1"
MAX_PROJECTION_BYTES = 8192
_EMPTY_LIST_FIELDS = (
    "Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules",
    "Dns", "DnsOptions", "DnsSearch", "ExtraHosts", "Links", "GroupAdd", "CapAdd",
)
_EMPTY_STRING_FIELDS = ("PidMode", "UTSMode", "UsernsMode", "Cgroup", "CgroupParent",
                        "VolumeDriver", "ContainerIDFile")
_REQUIRED_HOST_FIELDS = frozenset((*_EMPTY_LIST_FIELDS, *_EMPTY_STRING_FIELDS,
    "NetworkMode", "CgroupnsMode", "IpcMode", "Runtime", "Isolation", "PublishAllPorts",
    "PortBindings", "Privileged", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Tmpfs",
    "LogConfig", "RestartPolicy", "AutoRemove"))
_TMPFS = {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}
_ENDPOINT_STRINGS = ("Gateway", "IPAddress", "IPv6Gateway", "GlobalIPv6Address", "MacAddress")


def _deny() -> None:
    # Do not export a dangerous value, a host path, or arbitrary Docker metadata.
    raise ControlError("AGENT_DOCKER_CHANNELS_INVALID")


def _empty_list(value: Any) -> bool:
    return value is None or type(value) is list and len(value) == 0


def _empty_map(value: Any) -> bool:
    return value is None or type(value) is dict and len(value) == 0


def _hex(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _host_projection(host: Any) -> dict:
    if type(host) is not dict or not _REQUIRED_HOST_FIELDS <= set(host):
        _deny()
    if any(not _empty_list(host[key]) for key in _EMPTY_LIST_FIELDS):
        _deny()
    if any(type(host[key]) is not str or host[key] != "" for key in _EMPTY_STRING_FIELDS):
        _deny()
    if (host["NetworkMode"] != "none" or host["CgroupnsMode"] != "private"
            or host["IpcMode"] != "private" or host["Runtime"] != "runc"
            or host["Isolation"] not in ("", "default")
            or host["PublishAllPorts"] is not False or host["Privileged"] is not False
            or host["ReadonlyRootfs"] is not True or host["AutoRemove"] is not False
            or not _empty_map(host["PortBindings"])
            or type(host["CapDrop"]) is not list or host["CapDrop"] != ["ALL"]
            or type(host["SecurityOpt"]) is not list or host["SecurityOpt"] != ["no-new-privileges:true"]
            or type(host["Tmpfs"]) is not dict or host["Tmpfs"] != _TMPFS):
        _deny()
    log = host["LogConfig"]
    restart = host["RestartPolicy"]
    if (type(log) is not dict or set(log) != {"Type", "Config"}
            or log["Type"] != "none" or not _empty_map(log["Config"])
            or type(restart) is not dict or set(restart) != {"Name", "MaximumRetryCount"}
            or restart["Name"] != "no" or type(restart["MaximumRetryCount"]) is not int
            or restart["MaximumRetryCount"] != 0):
        _deny()
    # These fields are tagged omitempty in Docker's API model. Omission means
    # no per-container override; an explicit override must also be empty.
    for key in ("Annotations", "StorageOpt", "Sysctls"):
        if key in host and not _empty_map(host[key]):
            _deny()
    if "Init" in host and host["Init"] is not None and host["Init"] is not False:
        _deny()
    return {**{key: [] for key in _EMPTY_LIST_FIELDS},
        **{key: "" for key in _EMPTY_STRING_FIELDS},
        **{key: host[key] for key in ("NetworkMode", "CgroupnsMode", "IpcMode", "Runtime")},
        "Isolation": "",
        "PublishAllPorts": False, "PortBindings": {}, "Privileged": False, "ReadonlyRootfs": True,
        "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Tmpfs": dict(_TMPFS),
        "LogConfig": {"Type": "none", "Config": {}},
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": False,
        "Annotations": {}, "StorageOpt": {}, "Sysctls": {}, "Init": False}


def _config_projection(config: Any) -> dict:
    if type(config) is not dict or "Volumes" not in config or not _empty_map(config["Volumes"]):
        _deny()
    # ExposedPorts and Healthcheck are omitempty fields. An executable health
    # check is another process source even when the main entrypoint is pinned.
    if "ExposedPorts" in config and not _empty_map(config["ExposedPorts"]):
        _deny()
    health = config.get("Healthcheck")
    if health is not None and health != {"Test": ["NONE"]}:
        _deny()
    if "MacAddress" in config and config["MacAddress"] != "":
        _deny()
    return {"Volumes": {}, "ExposedPorts": {}, "Healthcheck": None, "MacAddress": ""}


def _network_projection(settings: Any) -> dict:
    if (type(settings) is not dict or not {"Networks", "Ports"} <= set(settings)
            or not _empty_map(settings["Ports"]) or type(settings["Networks"]) is not dict
            or set(settings["Networks"]) not in (set(), {"none"})):
        _deny()
    networks = settings["Networks"]
    if "none" in networks:
        endpoint = networks["none"]
        if (type(endpoint) is not dict or not set(_ENDPOINT_STRINGS) <= set(endpoint)
                or any(type(endpoint[key]) is not str or endpoint[key] != "" for key in _ENDPOINT_STRINGS)):
            _deny()
        for key in ("IPAMConfig", "DriverOpts"):
            if key in endpoint and not _empty_map(endpoint[key]):
                _deny()
        for key in ("Links", "Aliases", "DNSNames"):
            if key in endpoint and not _empty_list(endpoint[key]):
                _deny()
        for key in ("IPPrefixLen", "GlobalIPv6PrefixLen", "GwPriority"):
            if key in endpoint and (type(endpoint[key]) is not int or endpoint[key] != 0):
                _deny()
    # These legacy fields were removed from recent API models. If the daemon
    # still returns them, a nonempty value cannot be hidden by the projection.
    for key in ("Bridge", "Gateway", "IPAddress", "IPv6Gateway", "GlobalIPv6Address",
                "MacAddress", "LinkLocalIPv6Address"):
        if key in settings and (type(settings[key]) is not str or settings[key] != ""):
            _deny()
    for key in ("SecondaryIPAddresses", "SecondaryIPv6Addresses"):
        if key in settings and not _empty_list(settings[key]):
            _deny()
    return {"Ports": {}, "Networks": {"none": {key: "" for key in _ENDPOINT_STRINGS}}
            if networks else {}}


def _mount_projection(raw: dict, host: dict) -> list:
    mounts = raw.get("Mounts")
    if type(mounts) is not list or len(mounts) != 1 or type(mounts[0]) is not dict:
        _deny()
    mount = mounts[0]
    source = mount.get("Source")
    if (mount.get("Type") != "bind" or mount.get("Destination") != "/workspace"
            or mount.get("RW") is not False or mount.get("Propagation") != "rprivate"
            or type(source) is not str or not source.startswith("/") or source.startswith("//")
            or "\x00" in source or len(source) > 4096 or posixpath.normpath(source) != source
            or mount.get("Mode", "") not in ("", "ro")
            or mount.get("Name", "") != "" or mount.get("Driver", "") != ""):
        _deny()
    if "Mounts" in host:
        request = host["Mounts"]
        if type(request) is not list or len(request) != 1 or type(request[0]) is not dict:
            _deny()
        item = request[0]
        if (not {"Type", "Source", "Target", "ReadOnly"} <= set(item)
                or not set(item) <= {"Type", "Source", "Target", "ReadOnly", "Consistency", "BindOptions"}
                or item["Type"] != "bind" or item["Source"] != source or item["Target"] != "/workspace"
                or item["ReadOnly"] is not True or item.get("Consistency", "") != ""):
            _deny()
        options = item.get("BindOptions")
        if options is not None:
            if (type(options) is not dict
                    or not set(options) <= {"Propagation", "NonRecursive", "CreateMountpoint",
                        "ReadOnlyNonRecursive", "ReadOnlyForceRecursive"}
                    or options.get("Propagation", "") not in ("", "rprivate")
                    or any(options[key] is not False for key in set(options) - {"Propagation"})):
                _deny()
    return [{"Type": "bind", "Destination": "/workspace", "RW": False,
             "Propagation": "rprivate", "source_digest": digest(source)}]


def verify_agent_channels(raw_inspect: dict) -> dict:
    """Validate enumerated live Docker surfaces and return bounded public data.

    No fallback from absent raw fields is made. The caller must obtain this
    object from the positively owned container and perform its existing exact
    source/image/argv/environment checks. No callback, socket or effect occurs.
    """
    if type(raw_inspect) is not dict or not _hex(raw_inspect.get("Id")):
        _deny()
    host = raw_inspect.get("HostConfig")
    projection = {"schema": CHANNELS_SCHEMA, "container_id": raw_inspect["Id"],
        "HostConfig": _host_projection(host), "Config": _config_projection(raw_inspect.get("Config")),
        "NetworkSettings": _network_projection(raw_inspect.get("NetworkSettings")),
        "Mounts": _mount_projection(raw_inspect, host), "execution_authorized": False}
    projection["projection_digest"] = digest(projection)
    return verify_agent_channels_projection(projection)


def verify_agent_channels_projection(value: Any) -> dict:
    """Check public evidence structure and safe values, not runtime provenance."""
    try:
        encoded = canonical_bytes(value)
        if len(encoded) > MAX_PROJECTION_BYTES:
            _deny()
        value = json.loads(encoded)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ControlError("AGENT_DOCKER_CHANNELS_INVALID") from exc
    fields = {"schema", "container_id", "HostConfig", "Config", "NetworkSettings", "Mounts",
              "execution_authorized", "projection_digest"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != CHANNELS_SCHEMA
            or not _hex(value["container_id"]) or value["execution_authorized"] is not False
            or not _hex(value["projection_digest"])):
        _deny()
    host, config, network, mounts = (value[key] for key in ("HostConfig", "Config", "NetworkSettings", "Mounts"))
    if (type(host) is not dict or canonical_bytes(host) != canonical_bytes(_host_projection(host))
            or type(config) is not dict or canonical_bytes(config) != canonical_bytes(_config_projection(config))
            or type(network) is not dict or canonical_bytes(network) != canonical_bytes(_network_projection(network))
            or type(mounts) is not list or len(mounts) != 1 or type(mounts[0]) is not dict
            or set(mounts[0]) != {"Type", "Destination", "RW", "Propagation", "source_digest"}
            or mounts[0]["Type"] != "bind" or mounts[0]["Destination"] != "/workspace"
            or mounts[0]["RW"] is not False or mounts[0]["Propagation"] != "rprivate"
            or not _hex(mounts[0]["source_digest"])):
        _deny()
    body = {key: item for key, item in value.items() if key != "projection_digest"}
    try:
        if value["projection_digest"] != digest(body):
            _deny()
        return json.loads(encoded)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ControlError("AGENT_DOCKER_CHANNELS_INVALID") from exc
