from __future__ import annotations

from lantern.modules.base import Collector
from lantern.modules.company.gleif import GleifCollector
from lantern.modules.company.sec_edgar import SecEdgarCollector
from lantern.modules.darknet.hudson_rock import HudsonRockCollector
from lantern.modules.darknet.ransomware_live import RansomwareLiveCollector
from lantern.modules.domain.crtsh import CrtShCollector
from lantern.modules.domain.dns_doh import DnsDohCollector
from lantern.modules.domain.rdap import RdapCollector
from lantern.modules.domain.wayback import WaybackCollector
from lantern.modules.email.gravatar import GravatarCollector
from lantern.modules.email.xposedornot import XposedOrNotCollector
from lantern.modules.infra.abuseipdb import AbuseIPDBCollector
from lantern.modules.infra.ripestat import RipeStatCollector
from lantern.modules.infra.shodan_internetdb import ShodanInfraCollector
from lantern.modules.infra.virustotal import VirusTotalCollector
from lantern.modules.search.searchapi import SearchApiCollector
from lantern.modules.search.wikipedia import WikipediaCollector
from lantern.modules.username.github_users import GitHubUsersCollector
from lantern.modules.username.keybase import KeybaseCollector
from lantern.modules.username.whatsmyname import WhatsMyNameCollector


def default_collectors() -> list[Collector]:
    """Fresh collector instances — the CLI and the API both call this
    rather than keeping their own lists, so adding a new module can't
    silently stay registered in one entry point and not the other.

    Some collectors carry internal rate-limiter state (XposedOrNot, Shodan,
    SEC EDGAR, GLEIF), so callers that run for a while (the API) should
    call this once and reuse the result, not re-call it per request.
    """
    return [
        WhatsMyNameCollector(),
        GitHubUsersCollector(),
        KeybaseCollector(),
        XposedOrNotCollector(),
        GravatarCollector(),
        RdapCollector(),
        CrtShCollector(),
        DnsDohCollector(),
        WaybackCollector(),
        ShodanInfraCollector(),
        VirusTotalCollector(),
        AbuseIPDBCollector(),
        RipeStatCollector(),
        SecEdgarCollector(),
        GleifCollector(),
        RansomwareLiveCollector(),
        HudsonRockCollector(),
        SearchApiCollector(),
        WikipediaCollector(),
    ]
