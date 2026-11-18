"""Collect what to watch from mailers, and whole-word / whole-domain matching."""
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List, Set

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled public-suffix snapshot; no network
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    if v.startswith("www."):
        v = v[4:]
    return v


def is_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(normalize_domain(value)))


def registered_domain(host: str) -> str:
    ext = _extract(normalize_domain(host).lstrip("*."))
    return ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain


def domain_label(domain: str) -> str:
    return _extract(normalize_domain(domain)).domain


@lru_cache(maxsize=4096)
def _name_re(name: str):
    return re.compile(r"(?<![a-z0-9])" + re.escape(name.lower()) + r"(?![a-z0-9])")


@lru_cache(maxsize=4096)
def _domain_re(domain: str):
    return re.compile(r"(?<![a-z0-9.-])(?:www\.)?" + re.escape(domain.lower()) + r"(?![a-z0-9-])")


def mentions_name(text: str, name: str) -> bool:
    return len(name) >= 4 and bool(_name_re(name).search((text or "").lower()))


def mentions_domain(text: str, domain: str) -> bool:
    return bool(domain) and bool(_domain_re(domain).search((text or "").lower()))


@dataclass
class Targets:
    own_domains: Set[str] = field(default_factory=set)
    supplier_domains: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)           # own + supplier company names
    industries: Set[str] = field(default_factory=set)
    vendors: Set[str] = field(default_factory=set)
    org_domains: Dict[str, Set[str]] = field(default_factory=dict)  # own domain -> all own domains of that org

    @property
    def all_domains(self) -> Set[str]:
        return self.own_domains | self.supplier_domains

    def matches(self, text: str) -> List[tuple]:
        """[(target, target_type)] mentioned in text."""
        hits = [(d, "domain") for d in sorted(self.all_domains) if mentions_domain(text, d)]
        hits += [(n.lower(), "name") for n in sorted(self.names) if mentions_name(text, n)]
        return hits


def targets_for(mailers: Iterable) -> Targets:
    t = Targets()
    for m in mailers:
        own = {normalize_domain(d) for d in (m.watch_domains or []) if is_domain(d)}
        t.own_domains |= own
        for d in own:
            t.org_domains.setdefault(d, set()).update(own)
        t.names |= {n.strip() for n in (m.watch_names or []) if len(n.strip()) >= 4}
        for s in m.suppliers or []:
            if s.get("domain") and is_domain(s["domain"]):
                t.supplier_domains.add(normalize_domain(s["domain"]))
            if s.get("name") and len(s["name"].strip()) >= 4:
                t.names.add(s["name"].strip())
        t.industries |= set(m.industries or [])
        t.vendors |= set(m.vendors or [])
    t.supplier_domains -= t.own_domains
    return t


def active_targets() -> Targets:
    from apps.mailers.models import Mailer

    return targets_for(Mailer.objects.filter(is_active=True, organization__is_active=True))
