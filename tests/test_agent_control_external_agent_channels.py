"""One-field channel mutations against an explicit Docker-shaped unit fixture.

No Docker process is started. The fixture models Linux Docker inspect, including
the private IPC default observed in PR216 and the documented private cgroup/runc
defaults. This suite establishes validator behavior, never containment evidence.
"""
from __future__ import annotations

import copy
import unittest

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_channels import (
    CHANNELS_SCHEMA, MAX_PROJECTION_BYTES, verify_agent_channels, verify_agent_channels_projection,
)


def safe_inspect_fixture() -> dict:
    """Explicit unit double; no absent load-bearing field is filled by production."""
    return {"Id": "a" * 64, "Image": "sha256:" + "b" * 64,
        "HostConfig": {
            "NetworkMode": "none", "CgroupnsMode": "private", "IpcMode": "private",
            "PidMode": "", "UTSMode": "", "UsernsMode": "", "Cgroup": "", "CgroupParent": "",
            "Runtime": "runc", "Isolation": "", "Privileged": False, "ReadonlyRootfs": True,
            "PublishAllPorts": False, "PortBindings": {}, "AutoRemove": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges:true"],
            "LogConfig": {"Type": "none", "Config": {}},
            "Binds": None, "VolumesFrom": None, "VolumeDriver": "", "ContainerIDFile": "",
            "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
            "Dns": [], "DnsOptions": [], "DnsSearch": [], "ExtraHosts": None, "Links": None,
            "GroupAdd": None, "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m"},
            "Mounts": [{"Type": "bind", "Source": "/owned/readonly-worker", "Target": "/workspace",
                        "ReadOnly": True, "BindOptions": {"Propagation": "rprivate"}}],
        },
        "Config": {"Volumes": None, "Entrypoint": ["python3"], "Env": ["PATH=/usr/bin"],
                   "Cmd": ["-I", "-u", "/workspace/external_agent_fixture.py", "useful_completion"]},
        "Mounts": [{"Type": "bind", "Source": "/owned/readonly-worker", "Destination": "/workspace",
                    "Mode": "", "RW": False, "Propagation": "rprivate"}],
        "NetworkSettings": {"Ports": {}, "Networks": {"none": {
            "Gateway": "", "IPAddress": "", "IPv6Gateway": "", "GlobalIPv6Address": "", "MacAddress": "",
            "IPPrefixLen": 0, "GlobalIPv6PrefixLen": 0, "GwPriority": 0,
            "IPAMConfig": None, "Links": None, "Aliases": None, "DriverOpts": None, "DNSNames": None,
            "EndpointID": "", "NetworkID": ""}}},
    }


class ExternalAgentChannelsTests(unittest.TestCase):
    def rejects(self, mutation):
        raw = safe_inspect_fixture()
        mutation(raw)
        with self.assertRaisesRegex(ControlError, "AGENT_DOCKER_CHANNELS_INVALID"):
            verify_agent_channels(raw)

    def test_explicit_safe_fixture_projects_checked_channels_without_paths_or_environment(self):
        raw = safe_inspect_fixture()
        before = copy.deepcopy(raw)
        result = verify_agent_channels(raw)
        self.assertEqual(raw, before)
        self.assertEqual(result["schema"], CHANNELS_SCHEMA)
        self.assertEqual(result["container_id"], raw["Id"])
        self.assertEqual(result["Mounts"][0]["source_digest"], digest("/owned/readonly-worker"))
        self.assertFalse(result["execution_authorized"])
        encoded = canonical_bytes(result)
        self.assertLess(len(encoded), MAX_PROJECTION_BYTES)
        self.assertNotIn(b"/owned/readonly-worker", encoded)
        self.assertNotIn(b"PATH=", encoded)
        self.assertEqual(verify_agent_channels_projection(result), result)

    def test_empty_slice_and_map_representations_are_canonicalized(self):
        first, second = safe_inspect_fixture(), safe_inspect_fixture()
        for key, value in list(second["HostConfig"].items()):
            if value is None:
                second["HostConfig"][key] = []
        second["HostConfig"]["PortBindings"] = None
        second["HostConfig"]["LogConfig"]["Config"] = None
        second["Config"]["Volumes"] = {}
        second["HostConfig"]["Isolation"] = "default"
        self.assertEqual(verify_agent_channels(first), verify_agent_channels(second))

    def test_every_required_host_field_is_required(self):
        # Omitempty override fields are deliberately absent from this set.
        for key in set(safe_inspect_fixture()["HostConfig"]) - {"Mounts"}:
            with self.subTest(field=key):
                self.rejects(lambda raw, field=key: raw["HostConfig"].pop(field))

    def test_raw_container_and_network_census_fields_cannot_be_absent(self):
        for key in ("Id", "HostConfig", "Config", "Mounts", "NetworkSettings"):
            with self.subTest(field=key):
                self.rejects(lambda raw, field=key: raw.pop(field))
        for key in ("Networks", "Ports"):
            with self.subTest(field=key):
                self.rejects(lambda raw, field=key: raw["NetworkSettings"].pop(field))
        self.rejects(lambda raw: raw["Config"].pop("Volumes"))
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"]["none"].pop("Gateway"))

    def test_each_external_access_request_is_independently_rejected(self):
        mutations = {
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock"], "VolumesFrom": ["other:rw"],
            "Devices": [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm", "CgroupPermissions": "rwm"}],
            "DeviceRequests": [{"Driver": "nvidia", "Count": -1, "Capabilities": [["gpu"]]}],
            "DeviceCgroupRules": ["a *:* rwm"], "Dns": ["127.0.0.1"], "DnsOptions": ["use-vc"],
            "DnsSearch": ["owned.test"], "ExtraHosts": ["host.docker.internal:host-gateway"],
            "Links": ["other:alias"], "GroupAdd": ["999"], "CapAdd": ["SYS_ADMIN"],
            "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
            "PublishAllPorts": True, "VolumeDriver": "external", "ContainerIDFile": "/host/created-id",
        }
        for key, value in mutations.items():
            with self.subTest(field=key):
                self.rejects(lambda raw, field=key, item=value: raw["HostConfig"].update({field: item}))

    def test_namespace_sharing_and_unreviewed_runtime_are_independently_rejected(self):
        for key, value in (("NetworkMode", "host"), ("NetworkMode", "container:other"),
            ("IpcMode", "host"), ("IpcMode", "shareable"), ("IpcMode", "container:other"),
            ("IpcMode", ""), ("IpcMode", "none"), ("PidMode", "host"), ("PidMode", "container:other"),
            ("UTSMode", "host"), ("UsernsMode", "host"), ("CgroupnsMode", "host"),
            ("CgroupnsMode", ""), ("Cgroup", "container:other"), ("CgroupParent", "shared.slice"),
            ("Runtime", "nvidia"), ("Runtime", ""), ("Isolation", "process")):
            with self.subTest(field=key, value=value):
                self.rejects(lambda raw, field=key, item=value: raw["HostConfig"].update({field: item}))

    def test_additional_tmpfs_mount_or_daemon_override_is_rejected(self):
        self.rejects(lambda raw: raw["HostConfig"]["Tmpfs"].update({"/run": "rw"}))
        for key, value in (("Annotations", {"runtime.hook": "external"}), ("StorageOpt", {"size": "1G"}),
            ("Sysctls", {"net.ipv4.ip_forward": "1"}), ("Init", True)):
            with self.subTest(field=key):
                self.rejects(lambda raw, field=key, item=value: raw["HostConfig"].update({field: item}))

    def test_effective_and_requested_mount_channels_are_checked(self):
        for field, value in (("Type", "volume"), ("Destination", "/run"), ("RW", True),
                             ("Propagation", "rshared"), ("Mode", "rw"), ("Source", "/owned/../host")):
            with self.subTest(field=field):
                self.rejects(lambda raw, key=field, item=value: raw["Mounts"][0].update({key: item}))
        self.rejects(lambda raw: raw["Mounts"].append({"Type": "bind", "Destination": "/run"}))
        self.rejects(lambda raw: raw["HostConfig"]["Mounts"][0].update(Source="/var/run/docker.sock"))
        self.rejects(lambda raw: raw["HostConfig"]["Mounts"][0].update(ReadOnly=False))
        self.rejects(lambda raw: raw["HostConfig"]["Mounts"][0].update(VolumeOptions={"DriverConfig": {"Name": "external"}}))
        self.rejects(lambda raw: raw["HostConfig"]["Mounts"][0]["BindOptions"].update(Propagation="rshared"))
        self.rejects(lambda raw: raw["HostConfig"]["Mounts"][0]["BindOptions"].update(CreateMountpoint=True))

    def test_logging_healthcheck_restart_and_security_downgrade_are_rejected(self):
        self.rejects(lambda raw: raw["HostConfig"]["LogConfig"].update(Type="syslog"))
        self.rejects(lambda raw: raw["HostConfig"]["LogConfig"]["Config"].update({"syslog-address": "tcp://owned.test:514"}))
        self.rejects(lambda raw: raw["Config"].update(Healthcheck={"Test": ["CMD", "python3", "/alternate.py"]}))
        self.rejects(lambda raw: raw["HostConfig"]["RestartPolicy"].update(Name="always"))
        self.rejects(lambda raw: raw["HostConfig"]["SecurityOpt"].append("seccomp:unconfined"))
        self.rejects(lambda raw: raw["HostConfig"].update(Privileged=True))
        self.rejects(lambda raw: raw["HostConfig"].update(ReadonlyRootfs=False))
        self.rejects(lambda raw: raw["HostConfig"].update(AutoRemove=True))

    def test_connected_endpoint_or_published_port_cannot_hide_behind_network_none(self):
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"].update(bridge={}))
        self.rejects(lambda raw: raw["NetworkSettings"]["Ports"].update({"80/tcp": [{"HostPort": "8080"}]}))
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"]["none"].update(Gateway="172.17.0.1"))
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"]["none"].update(IPAddress="172.17.0.2"))
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"]["none"].update(DriverOpts={"external": "true"}))
        self.rejects(lambda raw: raw["NetworkSettings"].update(Gateway="172.17.0.1"))
        self.rejects(lambda raw: raw["Config"].update(ExposedPorts={"80/tcp": {}}))
        self.rejects(lambda raw: raw["Config"].update(Volumes={"/run": {}}))

    def test_canonical_types_cannot_substitute_false_or_empty_collections(self):
        for field, value in (("PublishAllPorts", 0), ("Privileged", 0), ("ReadonlyRootfs", 1),
                             ("AutoRemove", 0), ("Devices", {}), ("VolumesFrom", ""), ("PortBindings", [])):
            with self.subTest(field=field, value=value):
                self.rejects(lambda raw, key=field, item=value: raw["HostConfig"].update({key: item}))
        self.rejects(lambda raw: raw["HostConfig"]["RestartPolicy"].update(MaximumRetryCount=False))
        self.rejects(lambda raw: raw["NetworkSettings"]["Networks"]["none"].update(IPPrefixLen=False))

    def test_projection_is_copied_and_tampering_never_establishes_safe_runtime(self):
        projection = verify_agent_channels(safe_inspect_fixture())
        verified = verify_agent_channels_projection(projection)
        verified["HostConfig"]["Devices"].append("synthetic")
        self.assertEqual(projection["HostConfig"]["Devices"], [])
        for mutate in (lambda item: item["HostConfig"].update(DeviceRequests=[{"Count": -1}]),
            lambda item: item["HostConfig"].update(Isolation="default"),
            lambda item: item.update(execution_authorized=True), lambda item: item.pop("NetworkSettings"),
            lambda item: item.update(extra="unreviewed"), lambda item: item.update(container_id="other")):
            changed = copy.deepcopy(projection)
            mutate(changed)
            # Rehashing a forged unsafe projection must still fail its schema.
            if "projection_digest" in changed:
                changed["projection_digest"] = digest({key: value for key, value in changed.items() if key != "projection_digest"})
            with self.assertRaises(ControlError):
                verify_agent_channels_projection(changed)
        projection["projection_digest"] = "0" * 64
        with self.assertRaises(ControlError):
            verify_agent_channels_projection(projection)

    def test_projection_rejects_non_json_and_nonfinite_data_as_control_error(self):
        for value in ({"unknown": float("nan")}, {"unknown": object()}, None, []):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ControlError):
                    verify_agent_channels_projection(value)


if __name__ == "__main__":
    unittest.main()
