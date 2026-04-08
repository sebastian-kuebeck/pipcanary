import sys
import pkgutil

from distutils.sysconfig import get_python_lib


def load_modules(dirname):
    for importer, package_name, _ in pkgutil.iter_modules([dirname]):
        if package_name not in sys.modules:
            try:
                print("Loading package: %s..." % package_name)
                print("Package: %s" % package_name, file=sys.stderr)
                importer.find_module(package_name).load_module(  # type: ignore
                    package_name
                )
                del sys.modules[package_name]
            except ImportError:
                pass


if __name__ == "__main__":
    load_modules(get_python_lib())
