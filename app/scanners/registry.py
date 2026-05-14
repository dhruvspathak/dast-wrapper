from app.scanners.base import ScannerPlugin
from app.scanners.zap_scanner import ZAPScanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[ScannerPlugin]] = {}

    def register(self, plugin: type[ScannerPlugin]) -> None:
        self._plugins[plugin.name] = plugin

    def create(self, name: str) -> ScannerPlugin:
        try:
            plugin = self._plugins[name]
        except KeyError as exc:
            raise ValueError(f"Unknown scanner plugin: {name}") from exc
        return plugin()

    def list_plugins(self) -> list[str]:
        return sorted(self._plugins)


scanner_registry = ScannerRegistry()
scanner_registry.register(ZAPScanner)
