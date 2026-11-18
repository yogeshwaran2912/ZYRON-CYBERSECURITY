"""
ZYRON Cybersecurity Framework - Modules Registry
Exports the four core cybersecurity domains:
1. Bug Bounty Research
2. Red Team Operations
3. Penetration Testing
4. Cybersecurity Automation
"""

from modules.bug_bounty.main import BugBountyModule
from modules.red_team.main import RedTeamModule
from modules.penetration_testing.main import PenetrationTestingModule
from modules.automation.main import AutomationModule

__all__ = [
    "BugBountyModule",
    "RedTeamModule",
    "PenetrationTestingModule",
    "AutomationModule",
]
