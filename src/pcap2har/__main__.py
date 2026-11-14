"""Command-line entry point."""

import argparse
import logging

from .api import convert


def main() -> None:
    parser = argparse.ArgumentParser(description='Convert a packet capture and TLS key log to HAR.')
    parser.add_argument('--pcap', required=True, help='Input pcap or pcapng')
    parser.add_argument('--keys', required=True, help='TLS key log file')
    parser.add_argument('-o', '--out', required=True, help='Output HAR file')
    parser.add_argument('--tshark', help='TShark executable')
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    try:
        output = convert(args.pcap, args.keys, args.out, tshark=args.tshark)
    except KeyboardInterrupt:
        parser.exit(130, 'Cancelled\n')  # Shell convention: 128 + SIGINT (2).
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f'Error: {exc}\n')
    print(output)


if __name__ == '__main__':
    main()
