from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseCollector(ABC):
    @abstractmethod
    def collect(self, identifier: str) -> Dict[str, Any]:
        """Collect raw signals from external source or fixture."""
        pass
