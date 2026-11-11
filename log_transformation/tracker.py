from dataclasses import dataclass, field
from typing import Any

from log_engine.routing import route_log
from log_transformation.filter import valid_log


@dataclass
class Tracker:
    """Predicate for filter(): route every record, keep valid ones,
    and count and sample the rest."""
    sample_size: int = 3
    seen: int = 0                                   # total lines
    rejected: int = 0                               # failed valid_log
    unknown: int = 0                                # kind == "unknown"
    last_category: str = "unknown"
    route_examples: dict = field(default_factory=dict)   # first example per kind
    valid_samples: list = field(default_factory=list)
    invalid_samples: list = field(default_factory=list)
    unknown_samples: list = field(default_factory=list)

    def __call__(self, record: Any) -> bool:
        self.seen += 1
        kind, description = route_log(record)
        self.last_category = kind

        if kind not in self.route_examples:
            self.route_examples[kind] = (description, record)

        if kind == "unknown":
            self.unknown += 1
            if len(self.unknown_samples) < self.sample_size:
                self.unknown_samples.append(record)

        if valid_log(record):
            if len(self.valid_samples) < self.sample_size:
                self.valid_samples.append((kind, description, record))
            return True

        self.rejected += 1
        if len(self.invalid_samples) < self.sample_size:
            self.invalid_samples.append((description, record))
        return False
