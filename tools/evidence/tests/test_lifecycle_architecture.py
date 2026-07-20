import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
IOS_APP = "\n".join(
    path.read_text() for path in sorted((ROOT / "ios/App").rglob("*.swift"))
)
IOS_SHELL_WITHOUT_ADAPTER = "\n".join(
    path.read_text()
    for path in sorted((ROOT / "ios/Sources/WalletShell").rglob("*.swift"))
    if path.name != "RealEngine.swift"
)
SWIFT_EXECUTOR = (ROOT / "ios/Sources/WalletShell/EffectExecutor.swift").read_text()
SWIFT_REAL_ENGINE = (ROOT / "ios/Sources/WalletShell/RealEngine.swift").read_text()
ANDROID_EXECUTOR = (
    ROOT
    / "android/wallet-shell/src/main/kotlin/eu/advatar/wallet/shell/EffectExecutor.kt"
).read_text()


class LifecycleArchitectureTests(unittest.TestCase):
    def test_ios_app_cannot_construct_or_mutate_generated_core_directly(self):
        forbidden = (
            r"\bWalletEngine\s*\(",
            r"\.handleEventJson\s*\(",
            r"\.redactTransaction\s*\(",
            r"\.wipeTransactionLog\s*\(",
        )
        for pattern in forbidden:
            self.assertIsNone(
                re.search(pattern, IOS_APP),
                f"iOS application bypasses durable lifecycle: {pattern}",
            )

    def test_swift_executor_requires_the_concrete_coordinator(self):
        self.assertRegex(
            SWIFT_EXECUTOR,
            r"public\s+init\s*\(\s*lifecycle:\s*DurableLifecycleCoordinator",
        )
        self.assertNotIn("engine: WalletEngineDriving", SWIFT_EXECUTOR)
        self.assertNotIn("as? any DurableLifecycleRetrying", SWIFT_EXECUTOR)
        self.assertNotRegex(
            SWIFT_REAL_ENGINE,
            r"extension\s+WalletEngine\s*:\s*WalletEngineDriving",
        )
        self.assertIsNone(
            re.search(r"\bWalletEngine\s*\(", IOS_SHELL_WITHOUT_ADAPTER),
            "generated Core construction escaped its controlled adapter",
        )

    def test_android_executor_requires_the_concrete_coordinator(self):
        self.assertRegex(
            ANDROID_EXECUTOR,
            r"class\s+EffectExecutor\s*\(\s*"
            r"private\s+val\s+lifecycle:\s*DurableLifecycleCoordinator",
        )
        self.assertNotIn("engine as? DurableLifecycleRetrying", ANDROID_EXECUTOR)


if __name__ == "__main__":
    unittest.main()
