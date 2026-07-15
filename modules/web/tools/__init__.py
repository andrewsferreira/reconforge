"""ReconForge Web Module - Tool wrappers for web reconnaissance.

Author: Andrews Ferreira
"""

from modules.web.tools.curl_tool import CurlTool
from modules.web.tools.ffuf import FfufTool
from modules.web.tools.gobuster import GobusterTool
from modules.web.tools.nikto import NiktoTool
from modules.web.tools.nuclei import NucleiTool
from modules.web.tools.sqlmap import SqlmapTool
from modules.web.tools.wafw00f import Wafw00fTool
from modules.web.tools.whatweb import WhatwebTool
from modules.web.tools.wpscan import WpscanTool

__all__ = [
    "WhatwebTool",
    "FfufTool",
    "GobusterTool",
    "NiktoTool",
    "NucleiTool",
    "WpscanTool",
    "SqlmapTool",
    "Wafw00fTool",
    "CurlTool",
]
