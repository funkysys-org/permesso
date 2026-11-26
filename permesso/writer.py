"""Plain-language triage writer (offline, no API needed).

Turns technical findings into two customer-facing pieces:
- plain_meaning(): what the risk actually means for a non-expert
- (remediation stays technical: it is for whoever implements the fix)

The LLM hook in triage.enhance(llm=...) replaces this writer when an agent
runtime (e.g. Hermes) is connected; this module is the always-available
fallback so reports never ship raw scanner noise.
"""
from __future__ import annotations

from .findings import Finding, Severity

_MEANINGS: dict[str, str] = {
    "headers": (
        "I browser dei visitatori si fidano di quello che questo sito invia, "
        "ma mancano le protezioni standard: una pagina costruita ad hoc può "
        "eseguire script nelle sessioni dei visitatori (XSS) o usare il sito "
        "in frammenti/trappole."
    ),
    "tls": (
        "Le connessioni verso questo sito non sono pienamente fidate: i dati "
        "potrebbero essere leggibili in transito o l'identità del server non "
        "è verificabile. I visitatori vedono avvisi di sicurezza."
    ),
    "vuln": (
        "Una debolezza nota del software che serve il sito è raggiungibile "
        "dall'esterno. Gli attaccanti automatizzati cercano esattamente "
        "questo e possono sfruttarlo senza credenziali."
    ),
    "ssh": (
        "Il servizio SSH accetta impostazioni considerate deboli: gli attacchi "
        "automatici provano queste prime, per indovinare le credenziali."
    ),
    "hardening": (
        "La configurazione del server è sotto la soglia raccomandata: restano "
        "attive impostazioni predefinite che i tentativi di intrusione "
        "esplorano per prime."
    ),
    "info": (
        "Osservazione a basso impatto: utile per la pulizia, non urgente."
    ),
}

_EN: dict[str, str] = {
    "headers": (
        "Visitors' browsers trust what this site sends them, but standard "
        "protections are missing: a crafted page could run scripts inside a "
        "visitor's session (XSS) or frame the site to trick them."
    ),
    "tls": (
        "Connections to this site are not fully trustworthy: data may be "
        "readable in transit or the server's identity can't be verified — "
        "visitors may see security warnings."
    ),
    "vuln": (
        "A known weakness in the software serving this site is reachable from "
        "the internet. Automated attackers scan for exactly this and can "
        "exploit it without credentials."
    ),
    "ssh": (
        "The SSH service accepts settings considered weak; automated attacks "
        "try those first when guessing credentials."
    ),
    "hardening": (
        "The server's configuration is below the recommended baseline: "
        "default settings that intruders probe first are still active."
    ),
    "info": "Low-impact observation — useful for cleanup, not urgent.",
}

_LANGS = {"en": _EN, "it": _MEANINGS}

_HIGH_TONE = " Treat it as a priority: this is the kind of issue automated attacks find first."


_LANGS = {"en": _EN, "it": _MEANINGS}

# per-finding specifics (matched on title, lowercase) — beat the generic text
_SPECIFIC = {
    "en": [
        ("strict-transport-security",
         "Browsers can be forced onto plain HTTP (a downgrade attack) and what "
         "visitors send or see can be read or altered in transit."),
        ("content-security-policy",
         "Any script injected into the site runs with the visitor's full "
         "session — the classic XSS route, with no browser-side brake."),
        ("cookie without httponly",
         "A script on the page (or any XSS bug) can read that cookie and take "
         "over the visitor's session without ever seeing a password."),
        ("cookie without secure",
         "That cookie can travel over unencrypted HTTP and be picked up by "
         "anyone on the same network."),
        ("x-content-type-options",
         "Browsers may guess a file's type and execute an uploaded file as "
         "code instead of showing it."),
        ("x-frame-options",
         "Malicious pages can embed the site invisibly and trick visitors into "
         "clicks they never intended (clickjacking)."),
        ("server banner discloses",
         "The exact software version is public — attackers match known CVEs "
         "against it automatically, no guesswork needed."),
        ("has expired",
         "Browsers refuse the connection outright: the site is effectively "
         "down for every visitor, and data can be intercepted meanwhile."),
        ("expires soon",
         "When the certificate lapses the site goes dark for everyone until "
         "it is renewed — plan the renewal now."),
        ("self-signed",
         "Visitors get a security warning and nothing verifies the server's "
         "identity: anyone can impersonate it."),
    ],
    "it": [
        ("strict-transport-security",
         "Un malintenzionato può forzare il browser del visitatore su HTTP in "
         "chiaro (downgrade) e leggere o alterare quello che invia o vede."),
        ("content-security-policy",
         "Qualsiasi script iniettato nel sito gira con la sessione completa "
         "del visitatore: la classica via dell'XSS, senza freni."),
        ("cookie without httponly",
         "Uno script della pagina (o una bug XSS) può leggere quel cookie e "
         "prendere il posto del visitatore, senza mai vedere una password."),
        ("cookie without secure",
         "Quel cookie può viaggiare in HTTP in chiaro e essere intercettato "
         "da chi è sulla stessa rete."),
        ("x-content-type-options",
         "Il browser può indovinare il tipo di file ed eseguire un file "
         "caricato come codice invece di mostrarlo."),
        ("x-frame-options",
         "Pagine ostili possono incorporare il sito in modo invisibile e "
         "trickare i visitatori con click mai voluti (clickjacking)."),
        ("server banner discloses",
         "La versione esatta del software è pubblica: gli attaccanti la "
         "abbinano automaticamente ai CVE noti, senza dover cercare."),
        ("has expired",
         "I browser rifiutano la connessione: il sito è di fatto giù per "
         "tutti, e nel frattempo i dati possono essere intercettati."),
        ("expires soon",
         "Quando il certificato scade il sito si spegne per tutti finché non "
         "viene rinnovato: pianifica il rinnovo adesso."),
        ("self-signed",
         "I visitatori vedono un avviso di sicurezza e nessuno verifica "
         "l'identità del server: chiunque può impersonarlo."),
    ],
}


def _specific(finding: Finding, lang: str) -> str | None:
    title = finding.title.lower()
    for pattern, text in _SPECIFIC.get(lang, _SPECIFIC["en"]):
        if pattern in title:
            return text
    return None


def plain_meaning(finding: Finding, lang: str = "en") -> str:
    base = _specific(finding, lang) or _LANGS.get(lang, _EN).get(
        finding.category, _EN["info"])
    if finding.severity >= Severity.HIGH:
        return base + _HIGH_TONE
    return base
