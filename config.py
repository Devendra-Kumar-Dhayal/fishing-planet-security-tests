"""Shared configuration for Fishing Planet security tests."""
from pathlib import Path

# Game installation paths
GAME_DIR = Path("/home/nevdread/.steam/debian-installation/steamapps/common/Fishing Planet")
GAME_DATA_DIR = GAME_DIR / "FishingPlanet_Data"
GAME_ASSEMBLY = GAME_DIR / "GameAssembly.so"
UNITY_PLAYER = GAME_DIR / "UnityPlayer.so"
GAME_EXECUTABLE = GAME_DIR / "FishingPlanet.X86_64"

# IL2CPP paths
METADATA_FILE = GAME_DATA_DIR / "il2cpp_data" / "Metadata" / "global-metadata.dat"

# Streaming assets
STREAMING_ASSETS = GAME_DATA_DIR / "StreamingAssets"
EOS_CONFIG = STREAMING_ASSETS / "EOS" / "EpicOnlineServicesConfig.json"
FIREBASE_CONFIG = STREAMING_ASSETS / "google-services-desktop.json"
UNITY_SERVICES_CONFIG = STREAMING_ASSETS / "UnityServicesProjectConfiguration.json"
ADDRESSABLES_DIR = STREAMING_ASSETS / "aa" / "StandaloneLinux64"
ADDRESSABLES_SETTINGS = STREAMING_ASSETS / "aa" / "settings.json"

# Player data
PLAYER_PREFS = Path("/home/nevdread/.config/unity3d/Fishing Planet LLC/FishingPlanet/prefs")
PLAYER_LOG = Path("/home/nevdread/.config/unity3d/Fishing Planet LLC/FishingPlanet/Player.log")

# Process info
PROCESS_NAME = "FishingPlanet.X86_64"
GAME_MODULE = "GameAssembly.so"

# Known credentials (extracted from configs)
EOS_CLIENT_ID = "xyza7891brvj6uSDprRpCnLDGlYLR09W"
EOS_CLIENT_SECRET = "FzVUPVLr/mmyDYKlYPmBKDpWCP0ZsjBZViSzyFEX4G0"
EOS_PRODUCT_ID = "69c4c77e43fb4773b3c13b376c231ddd"
EOS_SANDBOX_ID = "441b1561f48746059211ab905f4abc93"
EOS_DEPLOYMENT_ID = "5d0f3e9dab23484e8fcaa637e22e7def"
EOS_ENCRYPTION_KEY = "2D4842EF6DC1B46D5FA8EE303810D1BA0EE83F8801B40FAECE7E3DBF2E02E66B"

FIREBASE_API_KEY = "AIzaSyCZUxG4jKslvRmJgu4rHQ20SVy1lw0i-fk"
FIREBASE_PROJECT_ID = "fishing-planet"
FIREBASE_PROJECT_NUMBER = "711770967650"

# Known target strings for metadata search
PREMIUM_TARGETS = [
    "HasPremium", "IsPremium", "FreeForPremium",
    "PremiumAccountBonus", "SetPremiumSalesAvailable",
    "AvailablePremiumGoldenSpins", "AvailableSpinsForPremium",
]

ECONOMY_TARGETS = [
    "SetMoney", "SetMoneyAndExp", "GetPlayerMoney",
    "SetCurrencyWithColor", "MoneyConverter",
    "ShowXpModificators", "RewardCreditsGoldItem",
]

ANTICHEAT_TARGETS = [
    "ObscuredInt", "ObscuredFloat", "ObscuredBool",
    "ObscuredString", "ObscuredDouble", "ObscuredLong",
    "SpeedHackDetector", "TimeCheatingDetector",
    "ObscuredCheatingDetector", "InjectionDetector",
]
