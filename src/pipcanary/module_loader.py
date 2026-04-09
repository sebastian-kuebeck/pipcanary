import os
import sys
import pkgutil
import importlib


def load_modules(dirname):
    for _, package_name, _ in pkgutil.iter_modules([dirname]):
        if package_name not in sys.modules:
            try:
                print("Loading package: %s..." % package_name)
                print("Package: %s" % package_name, file=sys.stderr)
                module = importlib.import_module(str(package_name))
                print("Module: %s" % module)
                del sys.modules[package_name]
            except Exception as e:
                print("Info: %s" % str(e))


if __name__ == "__main__":
    filedir = os.path.dirname(__file__)
    version = sys.version_info
    libdir = f"{filedir}/lib/python{version.major}.{version.minor}/site-packages"
    print("Loading modules from: %s..." % libdir)
    load_modules(libdir)
