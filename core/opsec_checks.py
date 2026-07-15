"""ReconForge OPSEC Checks - Safety validation before executing actions."""


from core.detection_map import get_detection_level, is_allowed


class OpsecChecker:
    """Validate actions against current OPSEC policy."""

    def __init__(self, mode: str = "normal", logger=None):
        self.mode = mode
        self.logger = logger

    def check(self, technique: str) -> bool:
        """Check if a technique is allowed. Returns True if allowed."""
        allowed = is_allowed(technique, self.mode)
        if not allowed and self.logger:
            level = get_detection_level(technique)
            desc = level.get("description", technique) if level else technique
            self.logger.warning(
                f"OPSEC BLOCKED: '{desc}' not allowed in {self.mode} mode "
                f"(noise: {level.get('noise', 'unknown') if level else 'unknown'})"
            )
        elif allowed and self.logger:
            warning = self.warn(technique)
            if warning:
                self.logger.warning(warning)
        return allowed

    def warn(self, technique: str) -> str | None:
        """Return a warning string if the technique is risky, else None."""
        level = get_detection_level(technique)
        if level and level.get("noise") in ("high", "very_high"):
            return f"⚠️  High detection risk: {level['description']} (noise: {level['noise']})"
        return None

    def set_mode(self, mode: str):
        self.mode = mode
