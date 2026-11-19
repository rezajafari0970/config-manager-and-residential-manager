"""Read au's explicitly published LTE/5G subscriber pools and their exceptions."""
from html.parser import HTMLParser
import ipaddress
import re
import unicodedata


class AccessLists(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "template"):
            self.hidden += 1
        if not self.hidden and tag in ("ol", "ul", "li"):
            self.parts.append(f"<{tag}>")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "template"):
            self.hidden = max(0, self.hidden - 1)
        if not self.hidden and tag in ("ol", "ul", "li"):
            self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data.replace("<", "&lt;").replace(">", "&gt;"))


SCOPE = "LTE NET/5G NET(スマートフォン/タブレット/4G LTE ケータイ)で使用しているグローバルアドレス"
DATA_NOTICE = "なお、LTE NET for DATA/5G NET for DATAで使用しているグローバルIPアドレスは非公開です。"
LISTS = re.compile(r" <ul> ((?:<li> [^<>]+ </li> ?)+)</ul> <ol> <li> 以下のアドレスを除く ([^<>]+) </li> </ol>")


def public_prefix(value):
    network = ipaddress.ip_network(value, strict=True)
    if "/" not in value or not network.is_global or network.is_multicast or network.prefixlen < (12 if network.version == 4 else 24):
        raise ValueError("invalid_kddi_prefix")
    return network


def prefixes(body):
    if len(body) > 2_000_000:
        raise ValueError("kddi_page_size")
    parser = AccessLists()
    parser.feed(body.decode("utf-8"))
    parser.close()
    page = " ".join(unicodedata.normalize("NFKC", " ".join(parser.parts)).split())
    if page.count(SCOPE) != 1 or page.count(DATA_NOTICE) != 1:
        raise ValueError("kddi_page_scope")
    after_scope = page.split(SCOPE, 1)[1]
    preface, sep, lists = after_scope.partition(DATA_NOTICE)
    match = LISTS.match(lists) if sep and "<" not in preface and len(preface) <= 100 else None
    if not match:
        raise ValueError("kddi_lists_changed")

    pools, footnoted = set(), []
    for item in re.findall(r"<li> ([^<>]+) </li>", match[1]):
        pool = public_prefix(item.removesuffix(" ※1"))
        pools.add(pool)
        if item.endswith(" ※1"):
            footnoted.append(pool)
    exceptions = {public_prefix(value) for value in match[2].split()}
    if (len(footnoted) != 1 or not exceptions or {pool.version for pool in pools} != {4, 6}
            or any(x.version != footnoted[0].version or not x.subnet_of(footnoted[0]) for x in exceptions)):
        raise ValueError("kddi_exclusions_changed")
    for excluded in sorted(exceptions):
        result = set()
        for pool in pools:
            if pool.version != excluded.version or not pool.overlaps(excluded):
                result.add(pool)
            elif excluded != pool and excluded.subnet_of(pool):
                result.update(pool.address_exclude(excluded))
        pools = result
    return sorted(pools, key=lambda p: (p.version, int(p.network_address), p.prefixlen))
