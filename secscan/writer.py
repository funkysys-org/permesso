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


def plain_meaning(finding: Finding, lang: str = "en") -> str:
    base = _LANGS.get(lang, _EN).get(finding.category, _EN["info"])
    if finding.severity >= Severity.HIGH:
        return base + _HIGH_TONE
    return base
