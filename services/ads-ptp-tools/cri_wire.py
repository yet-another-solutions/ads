#!/usr/bin/env python3
"""Minimal CRI v1 wire codec: the five RuntimeService messages we call.

Hand-rolled protobuf wire encoding/decoding (stdlib only, no protobuf
runtime). Field numbers mirror k8s.io/cri-api v1 api.proto; decoding is
strict about wire types and refuses unknown-state enums.
"""

from __future__ import annotations


def require(value, message):
    if not value:
        raise ValueError(message)


# --- primitive wire helpers ---


def varint(value):
    require(value >= 0, "negative varint unsupported")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def tag(number, wire):
    return varint(number << 3 | wire)


def pb_string(number, value):
    encoded = value.encode()
    return tag(number, 2) + varint(len(encoded)) + encoded


def pb_int(number, value):
    return tag(number, 0) + varint(value)


def pb_message(number, payload):
    return tag(number, 2) + varint(len(payload)) + payload


def pb_bool(number, value):
    return tag(number, 0) + varint(1 if value else 0) if value else b""


def reader(buf):
    """Yield (field_number, wire_type, value) for one message body."""
    index = 0
    end = len(buf)
    while index < end:
        key = 0
        shift = 0
        while True:
            require(index < end, "truncated protobuf tag")
            byte = buf[index]
            index += 1
            key |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        number, wire = key >> 3, key & 7
        require(number > 0, "invalid protobuf field number")
        if wire == 0:
            value = 0
            shift = 0
            while True:
                require(index < end, "truncated protobuf varint")
                byte = buf[index]
                index += 1
                value |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            yield number, wire, value
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                require(index < end, "truncated protobuf length")
                byte = buf[index]
                index += 1
                length |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            require(index + length <= end, "truncated protobuf bytes")
            yield number, wire, buf[index : index + length]
            index += length
        else:
            require(False, f"unsupported protobuf wire type {wire}")


def _u64(value):
    # Protobuf int64/uint64 arrive as unsigned varints; interpret as signed 64.
    return value - (1 << 64) if value >= (1 << 63) else value


# --- enums ---

POD_SANDBOX_STATES = {0: "SANDBOX_READY", 1: "SANDBOX_NOTREADY"}
CONTAINER_STATES = {
    0: "CONTAINER_CREATED",
    1: "CONTAINER_RUNNING",
    2: "CONTAINER_EXITED",
    3: "CONTAINER_UNKNOWN",
}


def sandbox_state_name(value):
    require(value in POD_SANDBOX_STATES, "unknown CRI sandbox state")
    return POD_SANDBOX_STATES[value]


def container_state_name(value):
    require(value in CONTAINER_STATES, "unknown CRI container state")
    return CONTAINER_STATES[value]


# --- requests ---


class VersionRequest:
    def __init__(self, version="0.1.0"):
        self.version = version

    def serialize(self):
        return pb_string(1, self.version) if self.version else b""


class ListPodSandboxRequest:
    def serialize(self):
        return b""


class PodSandboxStatusRequest:
    def __init__(self, pod_sandbox_id, verbose=True):
        self.pod_sandbox_id = pod_sandbox_id
        self.verbose = verbose

    def serialize(self):
        return pb_string(1, self.pod_sandbox_id) + (pb_bool(2, True) if self.verbose else b"")


class ListContainersRequest:
    def serialize(self):
        return b""


class ContainerStatusRequest:
    def __init__(self, container_id, verbose=True):
        self.container_id = container_id
        self.verbose = verbose

    def serialize(self):
        return pb_string(1, self.container_id) + (pb_bool(2, True) if self.verbose else b"")


# --- responses (decoded to plain dicts matching the crictl JSON contract) ---


def _metadata(buf):
    out = {"uid": "", "name": "", "namespace": "", "attempt": 0}
    for number, wire, value in reader(buf):
        require(wire == 2 or (wire == 0 and number == 4), "invalid metadata wire type")
        if number == 1:
            out["name"] = value.decode()
        elif number == 2:
            out["uid"] = value.decode()
        # canonical key order enforced at return
        elif number == 3:
            out["namespace"] = value.decode()
        elif number == 4:
            out["attempt"] = value
    # canonical order: uid, name, namespace, attempt
    return {
        "uid": out["uid"],
        "name": out["name"],
        "namespace": out["namespace"],
        "attempt": out["attempt"],
    }


def _string_map(buf):
    key = ""
    out = {}
    for number, wire, value in reader(buf):
        require(wire == 2, "invalid map entry wire type")
        if number == 1:
            key = value.decode()
        elif number == 2:
            out[key] = value.decode()
    return out


def _sandbox(buf):
    item = {
        "id": "",
        "state": "SANDBOX_READY",
        "createdAt": 0,
        "metadata": {},
        "labels": {},
        "annotations": {},
        "runtimeHandler": "",
    }
    for number, wire, value in reader(buf):
        if number == 1:
            require(wire == 2, "invalid sandbox id wire type")
            item["id"] = value.decode()
        elif number == 2:
            require(wire == 2, "invalid sandbox metadata wire type")
            item["metadata"] = _metadata(value)
        elif number == 3 and wire == 0:
            item["state"] = sandbox_state_name(value)
        elif number == 4 and wire == 0:
            item["createdAt"] = _u64(value)
        elif number == 5 and wire == 2:
            item["labels"].update(_string_map(value))
        elif number == 6 and wire == 2:
            item["annotations"].update(_string_map(value))
        elif number == 7 and wire == 2:
            item["runtimeHandler"] = value.decode()
    return item


def _container(buf):
    item = {
        "id": "",
        "podSandboxId": "",
        "state": "CONTAINER_CREATED",
        "createdAt": 0,
        "metadata": {},
        "image": {"image": ""},
        "imageRef": "",
        "labels": {},
        "annotations": {},
    }
    for number, wire, value in reader(buf):
        if number == 1:
            require(wire == 2, "invalid container id wire type")
            item["id"] = value.decode()
        elif number == 2:
            require(wire == 2, "invalid container sandbox wire type")
            item["podSandboxId"] = value.decode()
        elif number == 3:
            require(wire == 2, "invalid container metadata wire type")
            item["metadata"] = _metadata(value)
        elif number == 4:
            require(wire == 2, "invalid container image wire type")
            image = ""
            for sub, sub_wire, sub_value in reader(value):
                require(sub == 1 and sub_wire == 2, "invalid image spec wire type")
                image = sub_value.decode()
            item["image"] = {"image": image}
        elif number == 5:
            require(wire == 2, "invalid container imageRef wire type")
            item["imageRef"] = value.decode()
        elif number == 6 and wire == 0:
            item["state"] = container_state_name(value)
        elif number == 7 and wire == 0:
            item["createdAt"] = _u64(value)
        elif number == 8 and wire == 2:
            item["labels"].update(_string_map(value))
        elif number == 9 and wire == 2:
            item["annotations"].update(_string_map(value))
    return item


def _container_status(buf):
    status = {
        "id": "",
        "state": "CONTAINER_CREATED",
        "metadata": {},
        "imageRef": "",
        "labels": {},
        "annotations": {},
    }
    for number, wire, value in reader(buf):
        if number == 1:
            require(wire == 2, "invalid status id wire type")
            status["id"] = value.decode()
        elif number == 2:
            require(wire == 2, "invalid status metadata wire type")
            status["metadata"] = _metadata(value)
        elif number == 3 and wire == 0:
            status["state"] = container_state_name(value)
        elif number == 9:
            require(wire == 2, "invalid status imageRef wire type")
            status["imageRef"] = value.decode()
        elif number == 12 and wire == 2:
            status["labels"].update(_string_map(value))
        elif number == 13 and wire == 2:
            status["annotations"].update(_string_map(value))
    return status


def _sandbox_status(buf):
    status = {
        "id": "",
        "state": "SANDBOX_READY",
        "metadata": {},
        "labels": {},
        "annotations": {},
    }
    for number, wire, value in reader(buf):
        if number == 1:
            require(wire == 2, "invalid sandbox status id wire type")
            status["id"] = value.decode()
        elif number == 2:
            require(wire == 2, "invalid sandbox status metadata wire type")
            status["metadata"] = _metadata(value)
        elif number == 3 and wire == 0:
            status["state"] = sandbox_state_name(value)
        elif number == 7 and wire == 2:
            status["labels"].update(_string_map(value))
        elif number == 8 and wire == 2:
            status["annotations"].update(_string_map(value))
    return status


def _info_map(entries):
    import json

    out = {}
    for buf in entries:
        key, value = "", ""
        for number, wire, item in reader(buf):
            require(wire == 2, "invalid info entry wire type")
            if number == 1:
                key = item.decode()
            elif number == 2:
                value = item.decode()
        try:
            out[key] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            out[key] = value
    # containerd verbose responses nest every info entry under one "info" key
    # (its own Info map); flatten that single-entry wrapper to the crictl shape.
    nested = out.get("info")
    if isinstance(nested, dict):
        for key, value in nested.items():
            out.setdefault(key, value)
        del out["info"]
    return out


class VersionResponse:
    def __init__(self):
        self.version = ""
        self.runtime_name = ""
        self.runtime_version = ""
        self.runtime_api_version = ""

    def parse(self, buf):
        for number, wire, value in reader(buf):
            require(wire == 2, "invalid version wire type")
            if number == 1:
                self.version = value.decode()
            elif number == 2:
                self.runtime_name = value.decode()
            elif number == 3:
                self.runtime_version = value.decode()
            elif number == 4:
                self.runtime_api_version = value.decode()
        return self


class ListPodSandboxResponse:
    def __init__(self):
        self.items = []

    def parse(self, buf):
        for number, wire, value in reader(buf):
            if number == 1:
                require(wire == 2, "invalid sandbox item wire type")
                self.items.append(_sandbox(value))
        return self


class PodSandboxStatusResponse:
    def __init__(self):
        self.status = {}
        self.info = {}

    def parse(self, buf):
        infos = []
        for number, wire, value in reader(buf):
            if number == 1:
                require(wire == 2, "invalid sandbox status wire type")
                self.status = _sandbox_status(value)
            elif number == 2:
                require(wire == 2, "invalid sandbox info wire type")
                infos.append(value)
        self.info = _info_map(infos)
        return self


class ListContainersResponse:
    def __init__(self):
        self.containers = []

    def parse(self, buf):
        for number, wire, value in reader(buf):
            if number == 1:
                require(wire == 2, "invalid container item wire type")
                self.containers.append(_container(value))
        return self


class ContainerStatusResponse:
    def __init__(self):
        self.status = {}
        self.info = {}

    def parse(self, buf):
        infos = []
        for number, wire, value in reader(buf):
            if number == 1:
                require(wire == 2, "invalid container status wire type")
                self.status = _container_status(value)
            elif number == 2:
                require(wire == 2, "invalid container info wire type")
                infos.append(value)
        self.info = _info_map(infos)
        return self


RESPONSES = {
    "Version": VersionResponse,
    "ListPodSandbox": ListPodSandboxResponse,
    "PodSandboxStatus": PodSandboxStatusResponse,
    "ListContainers": ListContainersResponse,
    "ContainerStatus": ContainerStatusResponse,
}
