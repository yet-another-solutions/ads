from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

from kubernetes.client.exceptions import ApiException


class FakeSessionKube:
    """Named GET/create only; no list, patch, delete, exec, or implicit bind."""

    def __init__(self):
        self.objects = {}
        self.calls = []
        self.before_create = None
        self.after_create = None

    async def named_pvc(self, name):
        self.calls.append(("get", "PersistentVolumeClaim", name))
        return deepcopy(self.objects.get(("PersistentVolumeClaim", name)))

    async def deployment(self, name):
        self.calls.append(("get", "Deployment", name))
        return deepcopy(self.objects.get(("Deployment", name)))

    def put(self, body):
        obj = deepcopy(body)
        obj["metadata"].update(uid=str(uuid4()), resourceVersion="1")
        self.objects[(obj["kind"], obj["metadata"]["name"])] = obj
        return obj

    async def create(self, body):
        if self.before_create:
            await self.before_create(body)
        key = (body["kind"], body["metadata"]["name"])
        if key in self.objects:
            raise ApiException(status=409)
        self.put(body)
        self.calls.append(("create", *key))
        if self.after_create:
            await self.after_create(body)

    async def create_pvc(self, body):
        await self.create(body)

    async def create_deployment(self, body):
        await self.create(body)


class FakeTopics:
    def __init__(self, kube):
        self.kube = kube
        self.hook = None

    async def prepare(self, sandbox_id):
        self.kube.calls.append(("topics-and-seek", str(sandbox_id)))
        if self.hook:
            await self.hook(sandbox_id)
