from enum import StrEnum


class SourceType(StrEnum):
    RSS = "rss"
    HTML = "html"
    PDF_URL = "pdf_url"
    PDF_UPLOAD = "pdf_upload"
    MISP = "misp"
    TAXII = "taxii"


class TLPLevel(StrEnum):
    WHITE = "WHITE"
    GREEN = "GREEN"


class SourceCategory(StrEnum):
    TRUSTED = "trusted"
    KNOWN = "known"
    UNKNOWN = "unknown"


class AlertStatus(StrEnum):
    NEW = "new"
    ACKED = "acked"
    FALSE_POSITIVE = "false_positive"


class SourceStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    RUNNING = "running"


class StixType(StrEnum):
    INDICATOR = "indicator"
    THREAT_ACTOR = "threat-actor"
    ATTACK_PATTERN = "attack-pattern"
    RELATIONSHIP = "relationship"
    REPORT = "report"


class DedupAction(StrEnum):
    INSERT = "insert"
    MERGE = "merge"
