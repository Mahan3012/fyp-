import importlib

packages = {
    'requests': 'requests',
    'bs4': 'beautifulsoup4',
    'dns': 'dnspython',
    'weasyprint': 'weasyprint',
    'playwright': 'playwright',
    'flask': 'flask',
    'flask_cors': 'flask-cors',
    'dotenv': 'python-dotenv',
    'colorama': 'colorama',
    'reportlab': 'reportlab',
    'pytest': 'pytest'
}

print("=" * 60)
print("CHECKING INSTALLED PACKAGES")
print("=" * 60)

installed = []
missing = []

for import_name, pip_name in packages.items():
    try:
        module = importlib.import_module(import_name)
        version = getattr(module, '__version__', 'Unknown')
        print(f"OK     - {pip_name:20} - Version: {version}")
        installed.append(pip_name)
    except ImportError:
        print(f"MISSING - {pip_name:20}")
        missing.append(pip_name)

print("=" * 60)
print(f"Installed: {len(installed)} packages")
print(f"Missing: {len(missing)} packages")
if missing:
    print("\nMissing packages:")
    for pkg in missing:
        print(f"  - {pkg}")
print("=" * 60)
