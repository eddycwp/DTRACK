"""Parse Maven ``pom.xml`` files: direct dependencies and dependencyManagement.

Returns structured data used by the Java analyzer to (a) classify direct vs
transitive dependencies and (b) feed the Maven resolver for transitive expansion.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


def _local(tag: str) -> str:
    """Strip the XML namespace from a tag name."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


@dataclass
class Dep:
    group: str
    artifact: str
    version: Optional[str]
    scope: str = "compile"
    optional: bool = False
    classifier: Optional[str] = None
    type: str = "jar"
    raw: dict = field(default_factory=dict)


@dataclass
class Pom:
    group_id: Optional[str]
    artifact_id: str
    version: Optional[str]
    packaging: str = "jar"
    parent: Optional[dict] = None
    properties: dict = field(default_factory=dict)
    direct_deps: list = field(default_factory=list)   # list[Dep]
    managed_deps: list = field(default_factory=list)  # list[Dep]
    modules: list = field(default_factory=list)
    licenses: list = field(default_factory=list)      # list[str] license names/spdx


def _text(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None or elem.text is None:
        return None
    t = elem.text.strip()
    return t or None


def _props_to_dict(props_elem: Optional[ET.Element]) -> dict:
    d: dict = {}
    if props_elem is None:
        return d
    for child in props_elem:
        d[_local(child.tag)] = (child.text or "").strip()
    return d


def _dep_from_elem(dep_elem: ET.Element) -> Dep:
    g = a = v = None
    scope = "compile"
    optional = False
    classifier = None
    dtype = "jar"
    raw: dict = {}
    for child in dep_elem:
        name = _local(child.tag)
        raw[name] = (child.text or "").strip()
        if name == "groupId":
            g = (child.text or "").strip()
        elif name == "artifactId":
            a = (child.text or "").strip()
        elif name == "version":
            v = (child.text or "").strip()
        elif name == "scope":
            scope = (child.text or "").strip() or "compile"
        elif name == "optional":
            optional = (child.text or "").strip().lower() == "true"
        elif name == "classifier":
            classifier = (child.text or "").strip() or None
        elif name == "type":
            dtype = (child.text or "").strip() or "jar"
    return Dep(group=g, artifact=a, version=v, scope=scope, optional=optional,
               classifier=classifier, type=dtype, raw=raw)


def _parse_root(root: ET.Element) -> Pom:
    # root may carry a default namespace
    def child(parent: ET.Element, name: str) -> Optional[ET.Element]:
        for c in parent:
            if _local(c.tag) == name:
                return c
        return None

    group_id = _text(child(root, "groupId"))
    artifact_id = _text(child(root, "artifactId")) or ""
    version = _text(child(root, "version"))
    packaging = _text(child(root, "packaging")) or "jar"

    parent = None
    parent_elem = child(root, "parent")
    if parent_elem is not None:
        parent = {
            "groupId": _text(child(parent_elem, "groupId")),
            "artifactId": _text(child(parent_elem, "artifactId")),
            "version": _text(child(parent_elem, "version")),
            "relativePath": _text(child(parent_elem, "relativePath")),
        }

    properties = _props_to_dict(child(root, "properties"))
    # Built-in project properties (used by ${project.version} etc.)
    if group_id:
        properties.setdefault("project.groupId", group_id)
        properties.setdefault("pom.groupId", group_id)
    properties.setdefault("project.artifactId", artifact_id)
    properties.setdefault("pom.artifactId", artifact_id)
    if version:
        properties.setdefault("project.version", version)
        properties.setdefault("pom.version", version)
        properties.setdefault("version", version)

    direct_deps: list = []
    managed_deps: list = []
    deps_elem = child(root, "dependencies")
    if deps_elem is not None:
        for d in deps_elem:
            if _local(d.tag) == "dependency":
                dep = _dep_from_elem(d)
                if dep.group and dep.artifact:
                    direct_deps.append(dep)
    dm_elem = child(root, "dependencyManagement")
    if dm_elem is not None:
        dm_deps = child(dm_elem, "dependencies")
        if dm_deps is not None:
            for d in dm_deps:
                if _local(d.tag) == "dependency":
                    dep = _dep_from_elem(d)
                    if dep.group and dep.artifact:
                        managed_deps.append(dep)

    modules: list = []
    mod_elem = child(root, "modules")
    if mod_elem is not None:
        for m in mod_elem:
            if _local(m.tag) == "module":
                modules.append((m.text or "").strip())

    licenses: list = []
    lic_elem = child(root, "licenses")
    if lic_elem is not None:
        for lic in lic_elem:
            if _local(lic.tag) == "license":
                for sub in lic:
                    if _local(sub.tag) == "name":
                        name = (sub.text or "").strip()
                        if name:
                            licenses.append(name)

    return Pom(
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        packaging=packaging,
        parent=parent,
        properties=properties,
        direct_deps=direct_deps,
        managed_deps=managed_deps,
        modules=modules,
        licenses=licenses,
    )


def _resolve_props(value: Optional[str], props: dict, depth: int = 0) -> Optional[str]:
    """Expand ${...} placeholders using the supplied property map (best effort)."""
    if not value or "${" not in value or depth > 5:
        return value
    out = value
    for _ in range(5):
        if "${" not in out:
            break
        start = out.find("${")
        end = out.find("}", start)
        if end == -1:
            break
        key = out[start + 2:end]
        repl = props.get(key)
        if repl is None:
            # leave placeholder unresolved
            break
        out = out[:start] + repl + out[end + 1:]
    return out


def parse_pom_text(text: str, resolve: bool = True) -> Pom:
    root = ET.fromstring(text)
    pom = _parse_root(root)
    if resolve:
        for dep in pom.direct_deps + pom.managed_deps:
            if dep.version:
                dep.version = _resolve_props(dep.version, pom.properties)
        pom.version = _resolve_props(pom.version, pom.properties)
    return pom


def parse_pom_file(path: str, resolve: bool = True) -> Pom:
    with open(path, "r", encoding="utf-8") as f:
        return parse_pom_text(f.read(), resolve=resolve)
