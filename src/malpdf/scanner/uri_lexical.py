"""Torch-free pure-string lexical URL schema, PSL parser, and allowlist filters for v4 URI detection."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import ipaddress
import math
import re
from urllib.parse import unquote, urlsplit

import numpy as np

URI_LEXICAL_SCHEMA_VERSION = "uri_lexical_v4.2"

URI_LEXICAL_FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "domain_length",
    "is_domain_ip",
    "char_continuation_rate",
    "tld_legitimate_prob",
    "url_char_prob",
    "tld_length",
    "no_of_subdomains",
    "has_obfuscation",
    "no_of_obfuscated_char",
    "obfuscation_ratio",
    "no_of_letters_in_url",
    "letter_ratio_in_url",
    "no_of_digits_in_url",
    "digit_ratio_in_url",
    "no_of_equals_in_url",
    "no_of_qmark_in_url",
    "no_of_ampersand_in_url",
    "no_of_other_special_chars_in_url",
    "special_char_ratio_in_url",
    "path_length",
    "query_length",
    "has_at_symbol",
    "has_punycode",
    "brand_in_untrusted_host",
    "high_risk_tld",
    "suspicious_lure_path_token",
    "shortener_or_user_content_host",
    "host_digit_count",
    "host_digit_ratio",
    "host_hyphen_count",
    "host_entropy",
    "reg_domain_length",
    "subdomain_length",
    "host_char_prob",
    "path_digit_ratio",
)

URI_LOG1P_INDICES: tuple[int, ...] = (0, 1, 6, 7, 9, 11, 13, 15, 16, 17, 18, 20, 21, 28, 30, 32, 33)

_MULTI_LABEL_PSL: frozenset[str] = frozenset(
    """
    co.uk ac.uk gov.uk org.uk net.uk me.uk ltd.uk plc.uk sch.uk
    com.vn edu.vn gov.vn org.vn net.vn info.vn int.vn biz.vn
    com.au net.au org.au edu.au gov.au asn.au id.au
    co.jp ne.jp or.jp ac.jp go.jp ed.jp gr.jp lg.jp
    co.kr ne.kr or.kr re.kr pe.kr go.kr ac.kr
    com.br net.br org.br gov.br edu.br mil.br
    co.in net.in org.in gov.in ac.in res.in edu.in
    com.cn net.cn org.cn gov.cn edu.cn ac.cn
    com.tw org.tw gov.tw edu.tw net.tw
    com.sg org.sg gov.sg edu.sg net.sg
    com.hk org.hk gov.hk edu.hk net.hk
    co.nz org.nz govt.nz ac.nz net.nz
    co.za org.za gov.za ac.za net.za
    com.mx gob.mx edu.mx org.mx
    com.tr org.tr gov.tr edu.tr
    com.ar gob.ar edu.ar org.ar
    com.my gov.my edu.my org.my
    co.id go.id ac.id or.id web.id
    co.th go.th ac.th or.th in.th
    com.ph gov.ph edu.ph org.ph
    co.il org.il ac.il gov.il
    com.ua org.ua gov.ua edu.ua
    com.pl org.pl gov.pl edu.pl
    com.ru org.ru net.ru edu.ru gov.ru
    com.es nom.es org.es gob.es edu.es
    eu.org us.com uk.com de.com
    """.split()
)

_XML_XMP_NAMESPACE_HOSTS: frozenset[str] = frozenset(
    """
    ns.adobe.com w3.org purl.org schemas.openxmlformats.org schemas.microsoft.com
    xml.org aiim.org iptc.org ns.useplus.org prismstandard.org
    dublincore.org rdfs.org xmlns.com ns.exif.org ns.tiff.org
    """.split()
)

_XML_XMP_HOST_PREFIX_PATHS: tuple[tuple[str, str], ...] = (
    ("creativecommons.org", "/ns"),
    ("openoffice.org", "/xmlns"),
    ("pdfa.org", "/ns"),
    ("pdfa.org", "/pdfa/ns"),
    ("pdfa.org", "/pdfua/ns"),
)

_SHARED_USER_CONTENT_ROOTS: frozenset[str] = frozenset(
    """
    google.com docs.google.com drive.google.com sites.google.com
    github.com github.io gitlab.io bitbucket.org
    office.com forms.office.com microsoft.com microsoftonline.com live.com onedrive.live.com
    sharepoint.com amazonaws.com s3.amazonaws.com
    firebaseapp.com firebasestorage.googleapis.com storage.googleapis.com googleapis.com
    web.app dropbox.com canva.site notion.site workers.dev pages.dev netlify.app vercel.app
    blob.core.windows.net core.windows.net
    bit.ly tinyurl.com t.co cutt.ly is.gd rebrand.ly ngrok-free.app trycloudflare.com
    forms.gle 1drv.ms lnkd.in rb.gy ow.ly shorturl.at
    myftpupload.com ds.click weeblysite.com weebly.com wixsite.com godaddysites.com
    blogspot.com wordpress.com glitch.me herokuapp.com replit.app duckdns.org
    """.split()
)

_HOSTING_ABUSE_INDICATOR_ROOTS: frozenset[str] = frozenset(
    """
    forms.gle forms.office.com onedrive.live.com sharepoint.com
    firebaseapp.com firebasestorage.googleapis.com storage.googleapis.com
    web.app canva.site notion.site workers.dev pages.dev netlify.app vercel.app
    blob.core.windows.net s3.amazonaws.com
    bit.ly tinyurl.com t.co cutt.ly is.gd rebrand.ly ngrok-free.app trycloudflare.com
    1drv.ms lnkd.in rb.gy ow.ly shorturl.at
    myftpupload.com ds.click weeblysite.com godaddysites.com duckdns.org glitch.me
    """.split()
)

_SHARED_USER_CONTENT_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("docs.google.com", "/forms/"),
    ("sites.google.com", "/view/"),
    ("drive.google.com", "/uc"),
    ("onedrive.live.com", "/redir"),
)

_DUAL_USE_BENIGN_HOSTING_ROOTS: frozenset[str] = frozenset(
    """
    forms.gle forms.office.com onedrive.live.com sharepoint.com
    firebaseapp.com firebasestorage.googleapis.com storage.googleapis.com
    web.app canva.site notion.site workers.dev pages.dev netlify.app vercel.app
    blob.core.windows.net s3.amazonaws.com
    """.split()
)

_ALLOWLISTED_TLDS: frozenset[str] = frozenset(
    """
    gov edu mil
    gov.vn edu.vn gov.uk ac.uk edu.au gov.au gov.in ac.in gov.cn edu.cn
    gov.sg edu.sg gov.hk edu.hk govt.nz ac.nz gob.mx edu.mx gob.ar edu.ar
    gob.es edu.es edu.tw ac.jp go.jp ac.th go.th ac.il gov.il gov.ua edu.ua
    gov.pl edu.pl edu.my gov.my edu.ph gov.ph ac.za gov.za
    """.split()
)

_ALLOWLISTED_DOMAINS: frozenset[str] = frozenset(
    """
    doi.org ieee.org acm.org orcid.org arxiv.org neurips.cc nips.cc nist.gov nasa.gov irs.gov
    ietf.org rfc-editor.org iso.org w3.org apache.org gnu.org python.org mozilla.org
    springer.com elsevier.com sciencedirect.com nature.com wiley.com cambridge.org
    oup.com mdpi.com tandfonline.com wikipedia.org wikimedia.org creativecommons.org
    example.org example.com
    """.split()
)

_OFFICIAL_BRAND_ROOTS: dict[str, frozenset[str]] = {
    "microsoft": frozenset(
        {
            "microsoft.com",
            "microsoftonline.com",
            "live.com",
            "office.com",
            "azure.com",
            "windows.net",
            "visualstudio.com",
            "github.com",
            "aka.ms",
            "msn.com",
            "bing.com",
        }
    ),
    "office365": frozenset({"office.com", "microsoft.com", "microsoftonline.com"}),
    "onedrive": frozenset({"onedrive.live.com", "live.com", "sharepoint.com"}),
    "sharepoint": frozenset({"sharepoint.com", "microsoft.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "paypal": frozenset({"paypal.com", "paypalobjects.com"}),
    "apple": frozenset({"apple.com", "icloud.com", "cdn-apple.com"}),
    "adobe": frozenset({"adobe.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "google": frozenset(
        {
            "google.com",
            "googleapis.com",
            "googleusercontent.com",
            "googlevideo.com",
            "google.co.uk",
            "google.de",
            "google.fr",
            "google.co.jp",
            "google.ca",
            "google.com.au",
            "goo.gl",
            "youtube.com",
            "youtu.be",
        }
    ),
    "booking": frozenset({"booking.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "usps": frozenset({"usps.com"}),
    "amazon": frozenset({"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.co.jp"}),
    "netflix": frozenset({"netflix.com"}),
    "binance": frozenset({"binance.com"}),
    "coinbase": frozenset({"coinbase.com"}),
}

_BRAND_BOUNDARY_IN_HOST: frozenset[str] = frozenset({"booking"})
_BRAND_HOST_REGEXES: dict[str, re.Pattern[str]] = {
    brand: re.compile(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])") for brand in _BRAND_BOUNDARY_IN_HOST
}
_BRAND_PATH_TOKEN_RES: dict[str, re.Pattern[str]] = {
    brand: re.compile(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", re.IGNORECASE) for brand in _OFFICIAL_BRAND_ROOTS
}

_HIGH_RISK_TLDS: frozenset[str] = frozenset(
    "zip mov top xyz click tk ml gq cf ga pw icu buzz rest cfd sbs cam bar".split()
)

_PAYLOAD_OR_EXECUTABLE_SUFFIX = re.compile(
    r"\.(?:exe|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|dll|jar|zip|rar|7z|iso|img|lnk|docm|xlsm|pptm)(?:$|[?#])",
    re.IGNORECASE,
)

_LURE_PATH_TOKEN_RE = re.compile(
    r"(?<![a-z0-9])(?:login|signin|sign-in|oauth|auth|verify|confirm|recover|unlock|session|token|"
    r"wallet|password|passwd|credential|sso|webmail|secure|invoice-view|billing|"
    r"update-account|docusign|onedrive|sharepoint|booking)(?![a-z0-9])",
    re.IGNORECASE,
)

_PCT_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")
_OBFUSC_PCT_RE = re.compile(r"%(?:25[0-9a-fA-F]{2}|00|2[eE]|5[cC]|3[0-9]|4[1-9a-fA-F]|5[0-9aA]|6[1-9a-fA-F]|7[0-9aA])")
_IPV4_DOTTED_RE = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){3}")
_PLAINTEXT_URL_RE = re.compile(
    r"""https?://(?:\[[0-9a-fA-F:.]+\][^\s<>"'\)\]\}>\\]*|[^\s<>"'\)\]\}>\\]+)""",
    re.IGNORECASE,
)
_SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _clean_control_chars(uri: str) -> str:
    return "".join(ch for ch in uri.strip() if ord(ch) >= 32 and ch not in "\t\r\n")


def _host_matches(host: str, domains: frozenset[str]) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in domains)


def _split_url_host(raw_uri: str) -> tuple[str, str, str, str, str]:
    normalized = _clean_control_chars(raw_uri)
    candidate = normalized if "://" in normalized or ":" in normalized.split("/", 1)[0] else f"http://{normalized}"
    try:
        parts = urlsplit(candidate)
        scheme = (parts.scheme or "").lower()
        netloc = parts.netloc or ""
        host = (parts.hostname or "").lower().rstrip(".")
        path = parts.path or ""
        query = parts.query or ""
        return scheme, netloc, host, path, query
    except ValueError:
        rest = _SCHEME_PREFIX_RE.sub("", normalized, count=1)
        authority, _, pq = rest.partition("/")
        netloc = authority
        host_part = authority.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]").lower().rstrip(".")
        path, _, query = ("/" + pq if pq else "").partition("?")
        scheme = normalized.partition(":")[0].lower() if "://" in normalized else ""
        return scheme, netloc, host_part, path, query


def _is_ip_host(host: str) -> bool:
    return _parse_ip_address(host) is not None


def registrable_domain(host: str) -> str:
    """Return lowercase registrable domain using stdlib PSL rules without external dependencies."""
    clean = host.strip().lower().strip("[]").rstrip(".")
    if not clean:
        return ""
    addr = _parse_ip_address(clean)
    if addr is not None:
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        return str(addr)
    labels = [lbl for lbl in clean.split(".") if lbl]
    if len(labels) <= 2:
        return ".".join(labels)
    tail2 = f"{labels[-2]}.{labels[-1]}"
    if tail2 in _MULTI_LABEL_PSL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail2


def extract_tld(host: str) -> str:
    clean = host.strip().lower().strip("[]").rstrip(".")
    if not clean or _is_ip_host(clean) or "." not in clean:
        return ""
    labels = [lbl for lbl in clean.split(".") if lbl]
    if len(labels) < 2:
        return ""
    tail2 = f"{labels[-2]}.{labels[-1]}"
    if tail2 in _MULTI_LABEL_PSL:
        return tail2
    return labels[-1]


def canonicalize_extracted_uri(raw_uri: str, *, trim_trailing_punct: bool = False) -> tuple[str, str] | None:
    """Normalize URI whitespace and optionally strip prose trailing punctuation before percent-unquoting."""
    if not isinstance(raw_uri, str):
        return None
    cleaned = _clean_control_chars(raw_uri)
    if not cleaned:
        return None
    if trim_trailing_punct and cleaned.lower().startswith(("http://", "https://")):
        while cleaned:
            if cleaned[-1] in ".,;:)}>\"'":
                cleaned = cleaned[:-1]
            elif cleaned[-1] == "]":
                authority = cleaned.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
                if (
                    authority.startswith("[")
                    and cleaned.endswith(authority)
                    and cleaned.count("[") == cleaned.count("]")
                ):
                    break
                cleaned = cleaned[:-1]
            else:
                break
    if not cleaned:
        return None
    if len(cleaned) > 2048:
        cleaned = cleaned[:2048]
    try:
        decoded = unquote(cleaned)
    except Exception:
        decoded = cleaned
    return cleaned, decoded


def _parse_ip_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    clean = host.strip("[]")
    if not clean:
        return None
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass
    low = clean.lower()
    if low.startswith("0x") and re.fullmatch(r"0x[0-9a-f]{1,8}", low):
        return ipaddress.IPv4Address(int(low, 16))
    if clean.isascii() and clean.isdigit() and len(clean) <= 10 and 0 <= int(clean) <= 0xFFFFFFFF:
        return ipaddress.IPv4Address(int(clean))
    if _IPV4_DOTTED_RE.fullmatch(clean):
        octets: list[int] = []
        for part in clean.split("."):
            if len(part) > 1 and part.startswith("0"):
                if not all(ch in "01234567" for ch in part):
                    return None
                val = int(part, 8)
            else:
                val = int(part)
            if not 0 <= val <= 255:
                return None
            octets.append(val)
        return ipaddress.IPv4Address((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
    return None


def _is_disallowed_ip_host(host: str) -> bool:
    addr = _parse_ip_address(host)
    if addr is None:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_loopback or addr.is_link_local or addr.is_unspecified)


def _has_valid_public_dns_labels(host: str) -> bool:
    if "." not in host:
        return False
    labels = host.split(".")
    if len(labels) < 2 or any((not lbl or len(lbl) > 63) for lbl in labels):
        return False
    tld = labels[-1]
    if tld.isascii() and tld.isalpha() and 2 <= len(tld) <= 24:
        return True
    return tld.startswith("xn--") and len(tld) >= 6


def is_scorable_http_uri(raw_uri: str) -> bool:
    scheme, _, host, _, _ = _split_url_host(raw_uri)
    if scheme not in {"http", "https"} or not host:
        return False
    if _is_ip_host(host):
        return not _is_disallowed_ip_host(host)
    return _has_valid_public_dns_labels(host)


def is_xml_xmp_namespace_uri(raw_uri: str) -> bool:
    """Identify static PDF/XML/XMP metadata namespace URIs that are schema identifiers, not links."""
    cleaned = _clean_control_chars(raw_uri)
    if not cleaned:
        return False
    low = cleaned.lower()
    if low.startswith(("xmp:", "uuid:", "urn:")):
        return True
    scheme, _, host, path, _ = _split_url_host(cleaned)
    if scheme not in {"http", "https"} or not host:
        return False
    if _host_matches(host, _XML_XMP_NAMESPACE_HOSTS):
        return True
    path_low = path.lower()
    return any(
        (host == d or host.endswith(f".{d}")) and path_low.startswith(prefix)
        for d, prefix in _XML_XMP_HOST_PREFIX_PATHS
    )


def is_allowlisted_uri(raw_uri: str) -> bool:
    """Subdomain-aware closed high-trust allowlist excluding shared/user-content hosting roots."""
    if is_xml_xmp_namespace_uri(raw_uri):
        return True
    scheme, netloc, host, path, query = _split_url_host(raw_uri)
    if scheme not in {"http", "https"} or not host or _is_ip_host(host):
        return False
    if "@" in unquote(netloc) or any(lbl.startswith("xn--") for lbl in host.split(".")):
        return False
    if _PAYLOAD_OR_EXECUTABLE_SUFFIX.search(unquote(path + ("?" + query if query else ""))):
        return False
    if _host_matches(host, _SHARED_USER_CONTENT_ROOTS):
        return False
    if _host_matches(host, _ALLOWLISTED_DOMAINS):
        return True
    labels = [lbl for lbl in host.split(".") if lbl]
    if len(labels) >= 2 and labels[-1] in _ALLOWLISTED_TLDS:
        return True
    if len(labels) >= 3 and f"{labels[-2]}.{labels[-1]}" in _ALLOWLISTED_TLDS:
        return True
    return False


def extract_plain_text_urls(text: str, *, max_urls: int = 64) -> list[str]:
    """Extract bounded unique HTTP(S) URLs from decoded PDF content text."""
    if not text or max_urls <= 0:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in _PLAINTEXT_URL_RE.finditer(text):
        canon = canonicalize_extracted_uri(match.group(), trim_trailing_punct=True)
        if canon is None:
            continue
        raw_url, _ = canon
        if not is_scorable_http_uri(raw_url) or is_xml_xmp_namespace_uri(raw_url) or raw_url in seen:
            continue
        seen.add(raw_url)
        found.append(raw_url)
        if len(found) >= max_urls:
            break
    return found


def _char_continuation_rate(host: str) -> float:
    body = host.replace(".", "")
    if not body:
        return 0.0
    max_alpha = max_digit = max_spec = 0
    cur_type = ""
    cur_len = 0
    for ch in body:
        ctype = "a" if ch.isalpha() else ("d" if ch.isdigit() else "s")
        if ctype == cur_type:
            cur_len += 1
        else:
            cur_type = ctype
            cur_len = 1
        if ctype == "a" and cur_len > max_alpha:
            max_alpha = cur_len
        elif ctype == "d" and cur_len > max_digit:
            max_digit = cur_len
        elif ctype == "s" and cur_len > max_spec:
            max_spec = cur_len
    return float(min(1.0, (max_alpha + max_digit + max_spec) / float(len(body))))


def normalize_uri_for_lexical_features(raw_uri: str) -> tuple[str, str, str, str, str, str]:
    """Strip non-registrable www. and bare trailing / while keeping userinfo, port, query, fragment, and encoding."""
    cleaned = _clean_control_chars(raw_uri)[:2048]
    scheme, netloc, host, path, query = _split_url_host(cleaned)
    reg = registrable_domain(host)
    strip_www = bool(
        host.startswith("www.") and reg and host != reg and (host[4:] == reg or host[4:].endswith(f".{reg}"))
    )
    host_norm = host[4:] if strip_www else host
    body = _SCHEME_PREFIX_RE.sub("", cleaned, count=1) if scheme in {"http", "https"} else cleaned
    if strip_www and body:
        auth_end = len(body)
        for sep in ("/", "?", "#"):
            pos = body.find(sep)
            if 0 <= pos < auth_end:
                auth_end = pos
        authority = body[:auth_end]
        rest = body[auth_end:]
        if "@" in authority:
            userinfo, hostport = authority.rsplit("@", 1)
            if hostport.lower().startswith("www."):
                authority = f"{userinfo}@{hostport[4:]}"
        elif authority.lower().startswith("www."):
            authority = authority[4:]
        body = authority + rest
    path_norm = path
    if path == "/" and not query and "#" not in body and body.endswith("/"):
        body = body[:-1]
        path_norm = ""
    body_norm = body or host_norm
    return scheme, netloc, host_norm, path_norm, query, body_norm


def is_bare_dual_use_hosted_uri(raw_uri: str) -> bool:
    """Identify dual-use user-content hosting links lacking standalone high-precision phishing lexical cues."""
    _scheme, _netloc, host, path, _query, _body = normalize_uri_for_lexical_features(raw_uri)
    in_dual_use = _host_matches(host, _DUAL_USE_BENIGN_HOSTING_ROOTS) or any(
        (host == d or host.endswith(f".{d}")) and unquote(path).lower().startswith(pref)
        for d, pref in _SHARED_USER_CONTENT_PATH_PREFIXES
    )
    if not in_dual_use:
        return False
    vec = extract_url_lexical_features(raw_uri, tld_legit_probs={}, char_probs={})
    return (
        float(vec[2]) == 0.0
        and float(vec[8]) == 0.0
        and float(vec[22]) == 0.0
        and float(vec[23]) == 0.0
        and float(vec[24]) == 0.0
        and float(vec[25]) == 0.0
        and float(vec[26]) == 0.0
        and float(vec[13]) < 4.0
        and float(vec[7]) <= 1.0
    )


def _shannon_entropy_str(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return float(-sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values()))


def extract_url_lexical_features(
    raw_uri: str,
    *,
    tld_legit_probs: Mapping[str, float],
    char_probs: Mapping[str, float],
    default_tld_prob: float = 0.50,
    default_char_prob: float = 1e-3,
) -> np.ndarray:
    """Compute scheme-neutral, www/trailing-slash normalized 36D host-vs-path lexical feature vector."""
    scheme, netloc, host, path, query, body = normalize_uri_for_lexical_features(raw_uri)

    url_len = float(len(body))
    denom = max(url_len, 1.0)
    dom_len = float(len(host))
    is_ip = 1.0 if _is_ip_host(host) else 0.0

    ccr = _char_continuation_rate(host)
    tld_multi = extract_tld(host)
    tld_single = host.rsplit(".", 1)[-1] if ("." in host and not is_ip) else ""
    reg = registrable_domain(host)
    if is_ip or not tld_single:
        tld_legit = 0.0
        tld_len = 0.0
        n_sub = 0.0
        reg_dom_len = 0.0
        sub_len = 0.0
    else:
        if tld_multi and tld_multi in tld_legit_probs:
            tld_legit = float(tld_legit_probs[tld_multi])
        elif tld_single in tld_legit_probs:
            tld_legit = float(tld_legit_probs[tld_single])
        elif tld_single in _HIGH_RISK_TLDS:
            tld_legit = 0.05
        else:
            tld_legit = float(default_tld_prob)
        tld_len = float(len(tld_single))
        reg_dom_len = float(len(reg)) if reg else 0.0
        if reg and host.endswith(f".{reg}"):
            prefix = host[: -(len(reg) + 1)]
            n_sub = float(len([lbl for lbl in prefix.split(".") if lbl]))
            sub_len = float(len(prefix))
        else:
            n_sub = 0.0
            sub_len = 0.0

    body_low = body.lower()
    char_prob_sum = sum(float(char_probs.get(ch, default_char_prob)) for ch in body_low)
    url_char_p = float(char_prob_sum / denom) if body_low else float(default_char_prob)

    host_low = host.lower()
    host_char_p = (
        float(sum(float(char_probs.get(ch, default_char_prob)) for ch in host_low) / len(host_low))
        if host_low
        else float(default_char_prob)
    )
    host_digits = sum(1 for ch in host if ch.isascii() and ch.isdigit())
    host_digit_ratio = float(host_digits / max(len(host), 1)) if host else 0.0
    host_hyphens = host.count("-")
    host_entropy = _shannon_entropy_str(host_low.replace(".", ""))

    pq_raw = f"{path}?{query}" if query else path
    pq_digits = sum(1 for ch in pq_raw if ch.isascii() and ch.isdigit())
    path_digit_ratio = float(pq_digits / len(pq_raw)) if pq_raw else 0.0

    sep_idx = len(body)
    for sep in ("/", "?", "#"):
        pos = body.find(sep)
        if 0 <= pos < sep_idx:
            sep_idx = pos
    authority_part = body[:sep_idx]
    rest_pq = body[sep_idx:]
    at_in_netloc = "@" in netloc or "@" in unquote(netloc)
    netloc_pct_hits = len(_PCT_HEX_RE.findall(authority_part))
    rest_obfusc_hits = len(_OBFUSC_PCT_RE.findall(rest_pq))
    non_ascii_host = sum(1 for ch in host if ord(ch) > 127)
    n_obfusc_chars = float((netloc_pct_hits + rest_obfusc_hits) * 3 + non_ascii_host)
    has_obfusc = 1.0 if (n_obfusc_chars > 0.0 or at_in_netloc) else 0.0
    obfusc_ratio = float(min(1.0, n_obfusc_chars / denom))

    n_letters = sum(1 for ch in body if ch.isascii() and ch.isalpha())
    n_digits = sum(1 for ch in body if ch.isascii() and ch.isdigit())
    n_equals = body.count("=")
    n_qmark = body.count("?")
    n_amp = body.count("&")
    n_other_spec = sum(1 for ch in body if not (ch.isascii() and ch.isalnum()) and ch not in ("=", "?", "&"))

    path_len = float(len(path))
    query_len = float(len(query))
    has_at = 1.0 if at_in_netloc else 0.0
    has_puny = 1.0 if (any(lbl.startswith("xn--") for lbl in host.split(".")) if host else False) else 0.0

    untrusted_brand = 0.0
    if host:
        for brand, official in _OFFICIAL_BRAND_ROOTS.items():
            if _host_matches(host, official):
                continue
            pat_host = _BRAND_HOST_REGEXES.get(brand)
            matched = bool(pat_host.search(host)) if pat_host is not None else (brand in host)
            if matched:
                untrusted_brand = 1.0
                break
        if untrusted_brand == 0.0 and (
            _host_matches(host, _HOSTING_ABUSE_INDICATOR_ROOTS)
            or any(
                (host == d or host.endswith(f".{d}")) and unquote(path).lower().startswith(pref)
                for d, pref in _SHARED_USER_CONTENT_PATH_PREFIXES
            )
        ):
            path_q = unquote(path + "?" + query).lower()
            for brand, official in _OFFICIAL_BRAND_ROOTS.items():
                if not _host_matches(host, official) and _BRAND_PATH_TOKEN_RES[brand].search(path_q):
                    untrusted_brand = 1.0
                    break

    high_risk = 1.0 if tld_single in _HIGH_RISK_TLDS else 0.0
    lure_haystack = f"{host}/{unquote(path)}?{unquote(query)}"
    lure_tok = (
        1.0
        if (
            _LURE_PATH_TOKEN_RE.search(lure_haystack)
            or _PAYLOAD_OR_EXECUTABLE_SUFFIX.search(unquote(path + "?" + query))
        )
        else 0.0
    )
    is_user_content = (
        1.0
        if (
            _host_matches(host, _HOSTING_ABUSE_INDICATOR_ROOTS)
            or any(
                (host == d or host.endswith(f".{d}")) and unquote(path).lower().startswith(pref)
                for d, pref in _SHARED_USER_CONTENT_PATH_PREFIXES
            )
        )
        else 0.0
    )

    vec = np.array(
        [
            url_len,
            dom_len,
            is_ip,
            ccr,
            tld_legit,
            url_char_p,
            tld_len,
            n_sub,
            has_obfusc,
            n_obfusc_chars,
            obfusc_ratio,
            float(n_letters),
            float(n_letters) / denom,
            float(n_digits),
            float(n_digits) / denom,
            float(n_equals),
            float(n_qmark),
            float(n_amp),
            float(n_other_spec),
            float(n_other_spec) / denom,
            path_len,
            query_len,
            has_at,
            has_puny,
            untrusted_brand,
            high_risk,
            lure_tok,
            is_user_content,
            float(host_digits),
            host_digit_ratio,
            float(host_hyphens),
            host_entropy,
            reg_dom_len,
            sub_len,
            host_char_p,
            path_digit_ratio,
        ],
        dtype=np.float32,
    )
    return vec
