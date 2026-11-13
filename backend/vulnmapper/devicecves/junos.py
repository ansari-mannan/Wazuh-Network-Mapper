"""Juniper Junos OS: which CVEs a device's release is affected by, read from
Juniper's own CVE records (CVE JSON 5, ``containers.cna.affected``).

NVD does not answer this well for Junos: its configurations lag Juniper's
advisories and enumerate releases unevenly. Juniper, the CNA for its products,
states for every advisory which Junos OS releases are affected, in its own
release notation, so this module reads that statement directly
(vulnmapper.devicecves.juniper fetches and caches the records).

Release notation (Juniper's): ``<major>.<minor>R<n>[-S<n>][.<build>]``, e.g.
``22.4R3-S1.6`` is train 22.4, release 3, service release 1, build 6. Regular
releases are totally ordered by (major, minor, R, S, build). Special trains
(``15.1X49-D200``), feature releases (``15.1F6``) and Junos OS Evolved
(``-EVO``) are separate branches: they are never compared with a regular
release, so entries about them do not apply to a device running a regular
release, and the other way round.

Junos OS Evolved has its own blocks in the records (product "Junos OS
Evolved") and the same release notation with ``-EVO`` appended
(``22.2R3-S1-EVO``). A device running Evolved is decided from those blocks
only (:func:`evo_blocks`, :func:`decide` with ``evolved=True``): the suffix is
dropped from every version string and the regular rules apply. Evolved special
trains (``23.4X100-D20-EVO``) stay separate branches.

A record entry is a range ``[version, lessThan)`` (or ``lessThanOrEqual``)
with a status, optionally with ``changes``. Some records use ``changes`` as a
timeline over one train instead: ``status`` holds from the train's start, flips
at ``lessThan`` and flips again at each change, which may lie past
``lessThan`` (see :func:`_is_timeline`). Juniper's bounds are often a list
of fixed releases, one per release branch of a train: "before 19.2R1-S7,
19.2R3-S3" means 19.2R1 is fixed from S7 on, 19.2R3 from S3 on, and 19.2R2,
which has no fix of its own, is affected. Older records state their versions
in free text ("14.2 prior to 14.2R4-S9, 14.2R7-S7, 14.2R8 on EX4300 Series");
the forms found in Juniper's records are parsed below. Anything else gives
UNDECIDED for that CVE, never a guess.

How one record decides a device (:func:`decide`):

  * Each affected block is read on its own. A block for other platforms (its
    ``platforms`` field, or "on ..." in its product name) is skipped. A model
    this module cannot place (a part number) matches every platform block.
  * Within a block, an explicit unaffected entry covering the release wins
    over an affected one: Juniper states the release a flaw was introduced in,
    or a service release that does not carry it, as an unaffected entry beside
    a wider affected range.
  * Across blocks, affected wins, then undecided, then unaffected.
  * A block whose affected entries name trains below and above the device's
    train, while no entry of the record names that train at all, gives
    UNDECIDED (``train_not_listed``): Juniper does not assess releases past
    their end of engineering, so the record makes no claim either way. Entries
    of every block that applies to the model count: records often split one
    statement over several platform blocks, and a train fixed or stated
    unaffected in one of them is assessed.

Platform phrases that appear only in the description text (no structured
field) are not read, so a CVE limited that way is reported for every model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

AFFECTED, UNAFFECTED, UNDECIDED = "affected", "unaffected", "undecided"
INF = 10 ** 9

_REGULAR = re.compile(r"^(\d+)\.(\d+)(?:R(\d+)(?:-S(\d+))?(?:\.(\d+))?)?$")
_TRAIN_R = re.compile(r"^(\d+)\.(\d+)R$")                    # "12.3R": the train
_TRAIN_END = re.compile(r"^(\d+)\.(\d+|\*)\*?$")             # "20.2*", "21.*"
_OTHER = re.compile(r"^\d+\.\d+(?:X\d+(?:-D\d+)?(?:\.\d+)?|F\d*(?:-S\d+)?(?:-J\d+)?(?:\.\d+)?)\*?$"
                    r"|^\d+\.\d+(?:R\d+(?:-S\d+)?(?:\.\d+)?)?-EVO\*?$", re.I)
_DEVICE = re.compile(r"^(?:JUNOS\s+)?(\d+)\.(\d+)R(\d+)(?:-S(\d+))?(?:\.(\d+))?(-EVO)?\s*$", re.I)
_EVO = re.compile(r"-EVO\b", re.I)


@dataclass(frozen=True)
class Release:
    """A regular Junos release, or a point between releases (a train's start
    or end). ``build`` None: not stated."""
    major: int
    minor: int
    r: int = 0
    s: int = 0
    build: Optional[int] = None

    def key(self) -> tuple:
        return (self.major, self.minor, self.r, self.s, self.build or 0)

    @property
    def train(self) -> tuple:
        return (self.major, self.minor)


class Unparsed(Exception):
    """A version statement this module does not understand."""


def is_evolved(firmware: str) -> bool:
    """Whether a release string is Junos OS Evolved ("22.2R3-S1.2-EVO")."""
    m = _DEVICE.match(firmware or "")
    return bool(m and m.group(6))


def parse_device(firmware: str, evolved: bool = False) -> Optional[Release]:
    """"JUNOS 22.4R3-S1.6" -> Release(22, 4, 3, 1, 6); None when not a regular
    release. With ``evolved``, only an Evolved release ("22.2R3-S1.2-EVO") is
    parsed; without it, an Evolved release gives None."""
    m = _DEVICE.match(firmware or "")
    if not m or bool(m.group(6)) != evolved:
        return None
    return Release(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                   int(m.group(4) or 0), int(m.group(5)) if m.group(5) else None)


def _token(text: str):
    """One version token -> Release (regular release or train start),
    ("end", Release) for a train's end ("20.2*"), "other" for a special-train or
    feature release, None for the open start ("0"). Raises Unparsed."""
    t = re.sub(r"\s*\((?:pending)\)\s*$", "", text.strip(), flags=re.I)
    t = t.rstrip(",.").strip()
    if t in ("0", "*"):
        return None
    m = _REGULAR.match(t)
    if m:
        if m.group(3) is None:
            return Release(int(m.group(1)), int(m.group(2)), 0, 0, None)
        return Release(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                       int(m.group(4) or 0), int(m.group(5)) if m.group(5) else None)
    m = _TRAIN_R.match(t)
    if m:
        return Release(int(m.group(1)), int(m.group(2)))
    m = _TRAIN_END.match(t)
    if m and t.endswith("*"):
        minor = INF if m.group(2) == "*" else int(m.group(2))
        return ("end", Release(int(m.group(1)), minor, INF, INF, INF))
    if _OTHER.match(t):
        return "other"
    raise Unparsed(text)


def _tokens(text: str) -> list:
    return list(_parsed_tokens(text))


@lru_cache(maxsize=65536)
def _parsed_tokens(text: str) -> tuple:
    # Every device is compared with every record, so the same version strings
    # are parsed once per device; the result depends on the text alone and
    # its items are immutable. Unparsed is raised again each time (not cached).
    text = re.sub(r"^(\d+),(\d+)$", r"\1.\2", text.strip())   # "23,2" is 23.2 in one record
    text = re.sub(r"\(pending\)", " ", text, flags=re.I)        # "17.3R3-S7 (pending)"
    text = re.sub(r"\band(?=\d)", "and ", text)                 # "S12 and15.1R7-S4"
    parts = re.split(r",|\s+and to\s+|\s+and\s+|\s+or\s+|\s+to\s+|\s+", text)
    return tuple(_token(p) for p in parts if p.strip().strip(",."))


def _cmp(v: Release, t: Release) -> int:
    """-1/0/1. A bound with no build equals every build of its release; a bound
    with a build compared against a device with none and the same release is
    undecidable."""
    a, b = v.key()[:4], t.key()[:4]
    if a != b:
        return -1 if a < b else 1
    if t.build is None:
        return 0
    if v.build is None:
        raise Unparsed("device build not stated")
    return (v.build > t.build) - (v.build < t.build)


def _reached(v: Release, tokens: list) -> Optional[bool]:
    """Whether ``v`` has reached the release(s) ``tokens`` name, read as
    Juniper's per-branch list: the release on ``v``'s own branch (same train and
    R) if the list names one, else every listed release. None: the list names
    only special-train or feature releases, so it says nothing about ``v``."""
    regular = []
    for t in tokens:
        if t is None:
            regular.append(Release(-1, -1))
        elif isinstance(t, tuple):
            regular.append(t[1])
        elif t != "other":
            regular.append(t)
    if not regular:
        return None
    same = [t for t in regular if t.train == v.train and t.r == v.r and t.r]
    if same:
        return _cmp(v, min(same, key=Release.key)) >= 0
    top = max(regular, key=Release.key)
    if _cmp(v, top) >= 0:
        return True
    low = min(regular, key=Release.key)
    if _cmp(v, low) < 0:
        return False
    return False


def _started(v: Release, tokens: list) -> Optional[bool]:
    """Whether ``v`` is at or after a range start. A list of starts ("17.2R1-S3,
    17.2R3") is per branch like a list of fixes; a release between them on a
    branch the list does not name is undecidable."""
    regular = [t for t in tokens if t != "other"]
    if not regular:
        return None
    if any(t is None for t in regular):
        return True
    regular = [t[1] if isinstance(t, tuple) else t for t in regular]
    if len(regular) == 1:
        return _cmp(v, regular[0]) >= 0
    same = [t for t in regular if t.train == v.train and t.r == v.r and t.r]
    if same:
        return _cmp(v, min(same, key=Release.key)) >= 0
    if _cmp(v, min(regular, key=Release.key)) < 0:
        return False
    if _cmp(v, max(regular, key=Release.key)) >= 0:
        return True
    raise Unparsed("between listed starts")


def _below(v: Release, tokens: list, inclusive: bool) -> Optional[bool]:
    """Whether ``v`` is below the range's bound (a list of first fixed releases,
    or a train's end)."""
    if len(tokens) == 1 and isinstance(tokens[0], tuple):
        return v.key() <= tokens[0][1].key()
    if inclusive:
        regular = [t for t in tokens if isinstance(t, Release)]
        if len(regular) != len(tokens) or len(regular) != 1:
            if not regular:
                return None
            raise Unparsed("lessThanOrEqual list")
        return _cmp(v, regular[0]) <= 0
    reached = _reached(v, tokens)
    return None if reached is None else not reached


# Free-text forms Juniper used in records before it adopted structured ranges.
_FT_PRIOR = re.compile(
    r"^(?P<start>\S+)\s+(?:versions?\s+)?(?:prior to|prior ro|before)\s+(?P<fix>.+?)"
    r"(?:\s+on\s+(?P<on>.+?))?\s*[,.]?\s*$", re.I)
_FT_FROM = re.compile(r"^(?P<train>\S+)\s+(?:versions above and including|from)\s+(?P<start>\S+)\s+"
                      r"(?:and )?prior to\s+(?P<fix>.+?)\s*$", re.I)
_FT_FROM_TO = re.compile(r"^(?P<train>\S+)\s+releases\s+from\s+(?P<start>\S+)\s+to\s+(?P<end>\S+)\s*$", re.I)
_FT_TRAIN = re.compile(r"^(?P<start>\d+\.\d+(?:X\d+)?)\s+(?:(?:all\s+)?versions?|any)(?:\s+on\s+(?P<on>.+?))?\s*$",
                       re.I)
_FT_TWICE = re.compile(r"^(?P<start>\d+\.\d+)\s+(?P=start)$")
_FT_FIXED = re.compile(r"^(?P<fix>.+?),?\s+and (?:all )?subsequent releases (?:have|contain|include)\b.*$", re.I)
_FT_OLDER = re.compile(r"^(?:all |junos (?:os )?)?releases prior to (?:junos os )?(?P<fix>\S+?)"
                       r" are (?:not affected|unaffected)\b.*$", re.I)
_OPEN_START = ("0", "unspecified", "all", "any", "all version prior to", "all versions prior to")
_FT_ALL_PRIOR = re.compile(r"^all versions? prior to\s+(?P<fix>.+?)\s*$", re.I)


def normalise(entry: dict) -> dict:
    """A record's ``versions[]`` entry -> ``{"start": [tokens], "below":
    [tokens] or None, "inclusive", "status", "changes": [(tokens, status)],
    "on": platform text or None, "exact": bool}``. Raises Unparsed."""
    status = entry.get("status")
    version = re.sub(r"\s+", " ", str(entry.get("version") or "")).strip()
    bound = entry.get("lessThan")
    inclusive = False
    if bound is None and entry.get("lessThanOrEqual") is not None:
        bound, inclusive = entry["lessThanOrEqual"], True
    changes = [(_tokens(str(c.get("at") or "")), c.get("status"))
               for c in entry.get("changes") or [] if isinstance(c, dict)]
    out = {"status": status, "inclusive": inclusive, "changes": changes,
           "on": None, "exact": False}
    if bound is not None:
        start = [None] if version.lower() in _OPEN_START else _tokens(version)
        out.update(start=start, below=None if str(bound).strip().lower() in _OPEN_START
                   else _tokens(str(bound)))
        out["timeline"] = _is_timeline(out)
        return out
    low = version.lower()
    if low in _OPEN_START:
        out.update(start=[None], below=None)
        return out
    m = _FT_OLDER.match(version)
    if m:
        out.update(start=[None], below=_tokens(m.group("fix")), status=UNAFFECTED)
        return out
    m = _FT_FIXED.match(version)
    if m:
        out.update(start=_tokens(m.group("fix")), below=None, status=UNAFFECTED)
        return out
    m = _FT_ALL_PRIOR.match(version)
    if m:
        out.update(start=[None], below=_tokens(m.group("fix")))
        return out
    m = _FT_FROM_TO.match(version)
    if m:
        out.update(start=_tokens(m.group("start")), below=_tokens(m.group("end")), either=True)
        return out
    m = _FT_FROM.match(version)
    if m:
        out.update(start=_tokens(m.group("start")), below=_tokens(m.group("fix")))
        return out
    m = _FT_TRAIN.match(version) or _FT_TWICE.match(version)
    if m:
        start = _token(m.group("start"))
        if start == "other":
            out.update(start=["other"], below=["other"])
        else:
            out.update(start=[start], below=[("end", Release(start.major, start.minor, INF, INF, INF))],
                       inclusive=False)
        out["on"] = m.groupdict().get("on")
        return out
    m = _FT_PRIOR.match(version)
    if m:
        if all(t == "other" for t in _tokens(m.group("start"))):
            out.update(start=["other"], below=None)     # a special train: never a regular release
            return out
        out.update(start=_tokens(m.group("start")), below=_tokens(m.group("fix")), on=m.group("on"))
        return out
    out.update(start=_tokens(version), below=None, exact=True)
    return out


def _exact(v: Release, t) -> bool:
    """Whether ``v`` is the release a bare token names. A bare train ("22.1")
    names the whole train. A release with no service release ("15.1R4") may
    mean that release alone or its whole branch; decide only when both readings
    agree."""
    if t == "other" or isinstance(t, tuple):
        return False
    if t is None:
        return True
    if t.r == 0:
        return v.train == t.train
    if t.s == 0 and t.build is None:
        alone = v.key()[:4] == t.key()[:4]
        branch = v.train == t.train and v.r == t.r
        if alone != branch:
            raise Unparsed("release named without its service release")
        return alone
    return _cmp(v, t) == 0


_FLIP = {AFFECTED: UNAFFECTED, UNAFFECTED: AFFECTED}


def _is_timeline(entry: dict) -> bool:
    """Whether a range entry is Juniper's timeline form: ``version`` is a train,
    ``status`` holds from its start, the status flips at ``lessThan``, and
    ``changes`` at or past ``lessThan`` flip it again ("20.2 versions 20.2R2-S3
    and later, prior to 20.2R3-S2" is ``{version: 20.2, status: unaffected,
    lessThan: 20.2R2-S3, changes: [{at: 20.2R3-S2, status: unaffected}]}``).
    Read as a plain range, every change would fall outside it."""
    start, below = entry["start"], entry["below"]
    if entry["status"] not in _FLIP or not entry["changes"] or below is None:
        return False
    if len(start) != 1 or not isinstance(start[0], Release) or start[0].r:
        return False
    train = start[0].train
    bounds = [t for t in below if isinstance(t, Release) and t.train == train]
    if not bounds or len(bounds) != len(below):
        return False
    return any(isinstance(t, Release) and t.train == train and all(t.key() >= b.key() for b in bounds)
               for tokens, _ in entry["changes"] for t in tokens)


def entry_status(v: Release, entry: dict) -> Optional[str]:
    """The status ``entry`` (normalised) gives ``v``, None when it does not cover
    ``v``. Raises Unparsed."""
    start = entry["start"]
    if entry["exact"]:
        return entry["status"] if any(_exact(v, t) for t in start) else None
    if entry.get("timeline"):
        if v.train != start[0].train:
            return None
        reached = _reached(v, entry["below"])
        if reached is None:
            raise Unparsed("timeline bound")
        status = _FLIP[entry["status"]] if reached else entry["status"]
        for tokens, to in entry["changes"]:
            if _reached(v, tokens):
                status = to
        return status
    s = _started(v, start)
    if s is None or not s:
        return None
    if entry["below"] is not None and entry.get("either"):
        # "from A to B": whether B is included is not stated; decide only
        # when it makes no difference
        b = _below(v, entry["below"], True)
        if b != _below(v, entry["below"], False):
            raise Unparsed("range end inclusion not stated")
        if not b:
            return None
    elif entry["below"] is not None:
        b = _below(v, entry["below"], entry["inclusive"])
        if b is None or not b:
            return None
    status = entry["status"]
    for tokens, to in entry["changes"]:
        r = _reached(v, tokens)
        if r:
            status = to
    return status


# -- platforms -------------------------------------------------------------

_FAMILIES = ("vsrx", "csrx", "srx", "qfx", "ex", "mx", "vmx", "ptx", "acx", "nfx", "qfabric", "crpd", "vqfx")
_PLATFORM = re.compile(r"\b(vsrx|csrx|srx|qfx|ex|mx|vmx|ptx|acx|nfx|qfabric|crpd|vqfx)\s*(\d+[a-z]?\d*)?\s*(series)?",
                       re.I)


def platform_terms(text: str) -> Optional[list]:
    """Platform text -> ``[(family, model prefix or "")]``; None when it names
    every platform or none this module recognises."""
    low = (text or "").lower()
    if not low.strip() or "all products" in low or "all platforms" in low:
        return None
    terms = []
    for fam, num, series in _PLATFORM.findall(low):
        fam = fam.lower()
        num = (num or "").lower()
        if num.endswith("k"):                    # "QFX10K", "QFX5k"
            num = num[:-1]
        elif series and num.isdigit():           # "SRX5000 Series", "EX4300 Series"
            num = num.rstrip("0") or num[:1]
        terms.append((fam, num))
    return terms or None


def model_family(model: str) -> Optional[tuple]:
    """"ex4300-48t" -> ("ex", "ex4300-48t"); None for a model this module
    cannot place (a part number)."""
    low = (model or "").strip().lower()
    for fam in _FAMILIES:
        if low.startswith(fam) and (len(low) == len(fam) or low[len(fam)].isdigit()
                                    or low[len(fam)] in "-_ "):
            return fam, low
    return None


def platform_matches(model: str, texts: list) -> bool:
    """Whether a device of ``model`` is among the platforms ``texts`` name. A
    model that cannot be placed, or texts naming nothing recognisable, match."""
    place = model_family(model)
    if place is None:
        return True
    fam, low = place
    any_terms = False
    for text in texts:
        terms = platform_terms(text)
        if terms is None:
            return True
        any_terms = True
        for tfam, num in terms:
            fams = {tfam} | ({"vsrx"} if tfam == "srx" and not num else set())
            if fam in fams and low.startswith((fam if fam != tfam else tfam) + num):
                return True
    return not any_terms


# -- records ----------------------------------------------------------------

def _product(block: dict) -> Optional[str]:
    """A Juniper block's product name, lower case; None for another vendor."""
    vendor = str(block.get("vendor") or "").strip().lower()
    if not vendor.startswith("juniper"):
        return None
    return re.sub(r"\s+", " ", str(block.get("product") or "")).strip().lower()


def is_junos_block(block: dict) -> bool:
    product = _product(block)
    if product is None:
        return False
    return product == "junos" or (product.startswith("junos os") and "evolved" not in product)


def is_evolved_block(block: dict) -> bool:
    product = _product(block)
    return product is not None and product.startswith("junos os evolved")


def _strip_evo(value):
    return _EVO.sub("", value) if isinstance(value, str) else value


def _as_regular(block: dict) -> dict:
    """An Evolved block with ``-EVO`` dropped from its version strings."""
    versions = []
    for raw in block.get("versions") or []:
        if not isinstance(raw, dict):
            versions.append(raw)
            continue
        entry = {k: _strip_evo(v) for k, v in raw.items()}
        if isinstance(raw.get("changes"), list):
            entry["changes"] = [{**c, "at": _strip_evo(c.get("at"))} if isinstance(c, dict) else c
                                for c in raw["changes"]]
        versions.append(entry)
    return {**block, "versions": versions}


def _named_trains(entries: list) -> set:
    """The regular trains the given entries name (starts and bounds)."""
    out = set()
    for e in entries:
        for t in (e["start"] or []) + (e["below"] or []):
            r = t[1] if isinstance(t, tuple) else t
            if isinstance(r, Release) and r.major >= 0 and r.minor < INF:
                out.add(r.train)
    return out


def _block_applies(block: dict, model: str) -> bool:
    product = str(block.get("product") or "")
    on = re.search(r"\bon\s+(.+)$", product)
    texts = list(block.get("platforms") or []) + ([on.group(1)] if on else [])
    return not texts or platform_matches(model, texts)


def _record_trains(blocks: list, model: str) -> set:
    """The regular trains any entry of the blocks that apply to ``model`` names."""
    entries = []
    for block in blocks:
        if not _block_applies(block, model):
            continue
        for raw in block.get("versions") or []:
            try:
                entries.append(normalise(raw))
            except Unparsed:
                continue
    return _named_trains(entries)


def block_status(v: Release, block: dict, model: str, named_elsewhere: frozenset = frozenset()) -> tuple:
    """``(status, why)`` one affected block gives ``v``: AFFECTED, UNAFFECTED,
    UNDECIDED, or ``(None, "platform")`` when the block is for other platforms.
    ``named_elsewhere``: trains the record's other applicable blocks name."""
    if not _block_applies(block, model):
        return None, "platform"
    seen, undecided, entries = set(), [], []
    for raw in block.get("versions") or []:
        try:
            entry = normalise(raw)
            entries.append(entry)
            if entry["on"] and not platform_matches(model, [entry["on"]]):
                continue
            status = entry_status(v, entry)
        except Unparsed as e:
            undecided.append(str(e))
            continue
        if status in (AFFECTED, UNAFFECTED):
            seen.add(status)
    if UNAFFECTED in seen:
        # an explicit unaffected statement is the narrower one: Juniper states
        # the releases a flaw was introduced in, or a service release that
        # does not carry it, as unaffected entries beside a wider affected range
        return UNAFFECTED, "conflict" if AFFECTED in seen else None
    if AFFECTED in seen:
        return AFFECTED, None
    if undecided:
        return UNDECIDED, undecided[0]
    if str(block.get("defaultStatus")) == AFFECTED:
        return AFFECTED, "default"
    named = _named_trains(entries) | named_elsewhere
    stated = _named_trains([e for e in entries if e["status"] == AFFECTED])
    if v.train not in named and any(t < v.train for t in stated) and any(t > v.train for t in stated):
        # trains on both sides are stated, this one is not: Juniper does not
        # assess releases past their end of engineering, so no claim either way
        return UNDECIDED, "train_not_listed"
    return UNAFFECTED, None


def junos_blocks(affected) -> list:
    """The Junos OS blocks of a record's ``containers.cna.affected``."""
    return [b for b in affected if isinstance(b, dict) and is_junos_block(b)] \
        if isinstance(affected, list) else []


def evo_blocks(affected) -> list:
    """The Junos OS Evolved blocks of a record's ``containers.cna.affected``, as
    stated (``-EVO`` is dropped when they are decided)."""
    return [b for b in affected if isinstance(b, dict) and is_evolved_block(b)] \
        if isinstance(affected, list) else []


def decide(blocks: list, v: Release, model: str, evolved: bool = False) -> tuple:
    """``(status, why)`` the Junos OS ``blocks`` of one record give a device
    running ``v`` (:func:`parse_device`): AFFECTED, UNAFFECTED or UNDECIDED, or
    ``(None, None)`` when there are no blocks. ``why`` names the rule that
    decided, or None. ``evolved``: ``blocks`` are Evolved blocks
    (:func:`evo_blocks`) and ``v`` an Evolved release."""
    if not blocks:
        return None, None
    if evolved:
        blocks = [_as_regular(b) for b in blocks]
    named = frozenset(_record_trains(blocks, model or ""))
    results = [block_status(v, b, model or "", named) for b in blocks]
    for want in (AFFECTED, UNDECIDED, UNAFFECTED):
        hit = [why for st, why in results if st == want]
        if hit:
            return want, hit[0]
    return UNAFFECTED, "platform"
