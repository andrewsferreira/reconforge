"""ReconForge Web Module - Output parsers for web reconnaissance tools.

Author: Andrews Ferreira
"""

from modules.web.parsers.whatweb_parser import WhatwebParser
from modules.web.parsers.ffuf_parser import FfufParser
from modules.web.parsers.gobuster_parser import GobusterParser
from modules.web.parsers.nikto_parser import NiktoParser
from modules.web.parsers.nuclei_parser import NucleiParser
from modules.web.parsers.wpscan_parser import WpscanParser
from modules.web.parsers.wafw00f_parser import Wafw00fParser

__all__ = [
    "WhatwebParser",
    "FfufParser",
    "GobusterParser",
    "NiktoParser",
    "NucleiParser",
    "WpscanParser",
    "Wafw00fParser",
]
