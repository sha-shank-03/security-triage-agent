"""Offline pure integrity gates; no quality threshold or native integration."""

import json
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import patch

MODULES = (
    "tests.test_upgrade_gateway", "tests.test_upgrade_deadline", "tests.test_upgrade_events",
    "tests.test_upgrade_spend", "tests.test_upgrade_sandbox", "tests.test_upgrade_evaluation",
    "tests.test_upgrade_public",
)


def main():
    with ExitStack() as stack:
        for name in ("socket.socket", "socket.create_connection", "subprocess.Popen"):
            stack.enter_context(patch(name, side_effect=AssertionError("pure CI forbids socket/process launch")))
        suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"passed": result.wasSuccessful(), "methods": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "skipped": len(result.skipped), "quality_gate": False,
                      "native_integration": False, "sockets_process_launch_blocked": True}))
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == "__main__": raise SystemExit(main())
