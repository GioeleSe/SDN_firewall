"""
main.py  –  Entry point for the SDN Firewall
Starts ryu-manager programmatically so you can run:

    python main.py
    python main.py --verbose
    python main.py --ofp-tcp-listen-port 6653

All standard ryu-manager flags are forwarded to sys.argv.
"""

import sys
import os

# Ensure the project directory is on the path so firewall_app / firewall_wsgi
# can import each other regardless of where you invoke main.py from.
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)


def main():
    # Inject the app module path as the first positional argument that
    # ryu-manager expects (the app to load).
    app_path = os.path.join(PROJECT_DIR, 'firewall_app.py')

    # Preserve any extra flags the user passed  (e.g. --verbose)
    extra_args = sys.argv[1:]

    # Rewrite argv so ryu's manager sees:  ryu-manager firewall_app.py [flags]
    sys.argv = ['ryu-manager', app_path] + extra_args

    from ryu.cmd.manager import main as ryu_main
    ryu_main()


if __name__ == '__main__':
    main()
