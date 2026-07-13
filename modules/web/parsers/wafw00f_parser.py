"""ReconForge wafw00f Parser - Parse WAF detection output.

Author: Andrews Ferreira

Extracts:
- Detected WAF product name
- WAF vendor information
- Detection confidence
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class WafDetection:
    """A detected WAF."""
    product: str = ""
    vendor: str = ""
    detected: bool = False


@dataclass
class Wafw00fResult:
    """Complete wafw00f scan result."""
    waf_detected: bool = False
    detections: List[WafDetection] = field(default_factory=list)
    raw_output: str = ""

    @property
    def waf_names(self) -> List[str]:
        return [d.product for d in self.detections if d.detected]


class Wafw00fParser:
    """Parse wafw00f text output into structured data."""

    # Pattern: "The site <url> is behind <WAF> (<Vendor>)"
    DETECTED_RE = re.compile(
        r"is behind(?:\s+a)?\s+(.+?)(?:\s+WAF)?\s*(?:\((.+?)\))?$",
        re.IGNORECASE,
    )
    # Pattern: "No WAF detected"
    NO_WAF_RE = re.compile(r"no waf detected", re.IGNORECASE)

    def parse_text(self, text: str) -> Wafw00fResult:
        """Parse wafw00f text output.

        Args:
            text: wafw00f stdout or file contents.

        Returns:
            Wafw00fResult with detection data.
        """
        result = Wafw00fResult(raw_output=text)
        seen = set()

        for line in text.splitlines():
            line = line.strip()

            match = self.DETECTED_RE.search(line)
            if match:
                product = match.group(1).strip().rstrip(".")
                vendor = match.group(2).strip() if match.group(2) else ""
                key = (product.lower(), vendor.lower())
                if key in seen:
                    continue
                seen.add(key)
                result.waf_detected = True
                result.detections.append(WafDetection(
                    product=product,
                    vendor=vendor,
                    detected=True,
                ))
                continue

            if self.NO_WAF_RE.search(line):
                if not result.detections:
                    result.waf_detected = False

        return result

    def parse_file(self, file_path: Path) -> Wafw00fResult:
        """Parse wafw00f output file.

        Args:
            file_path: Path to wafw00f output.

        Returns:
            Wafw00fResult with detection data.
        """
        if not file_path.is_file():
            return Wafw00fResult()

        text = file_path.read_text(encoding="utf-8", errors="replace")
        return self.parse_text(text)
