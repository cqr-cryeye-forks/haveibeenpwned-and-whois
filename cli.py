import json
from argparse import ArgumentParser
from time import sleep

import requests
import whois


def parse_args(parser: ArgumentParser):
    parser.add_argument(
        '-d', '--domain',
        dest='domain',
        required=True,
        type=str,
        help="specify a domain"
    )
    parser.add_argument(
        '-k', '--api-key',
        dest='api_key',
        required=True,
        type=str,
        help="specify a have i been pwned api key"
    )
    parser.add_argument(
        '-o', '--output',
        dest='output',
        type=str,
        default='output.json',
        help="specify a output file, output in json format, default: output.json"
    )
    return parser.parse_args()


def get_emails(domain: str) -> list:
    # basically raises whois.parser.PywhoisError if domain not found or doesn't match
    # but I silenced it to just an Exception, because there is no need to process it further.
    try:
        w = whois.whois(domain)
    except Exception as e:
        print(e)
        print("This is fine, domain not found or doesn't match.")
        return []

    print(w)
    emails = w.get('emails', [])
    return emails if type(emails) is list else [emails]


def check(email: str, api_key: str, depth: int = 0):
    resp = requests.get(
        f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
            'hibp-api-key': api_key
        },
        params={'truncateResponse': 'false'},
        timeout=10
    )

    if resp.status_code == 200:
        data = resp.json()
        return data if type(data) is list else [data]
    elif resp.status_code == 429:
        if depth > 2:
            return []
        print(f"Status code: {resp.status_code}")
        wait = float(resp.headers.get('Retry-After'))
        print(f'retry in {wait}s]')
        sleep(wait)
        return check(email, api_key, depth + 1)

    else:
        print(f'Failed with status code: {resp.status_code}')
        print(resp.text)
        return []


def main():
    parser = ArgumentParser("This is app.")
    args = parse_args(parser)
    emails = get_emails(args.domain)
    breaches = []
    for email in emails:
        if not email:
            continue

        print(f"Searching... Email: {email}")
        try:
            breaches.extend(check(email, args.api_key))
        except Exception as e:
            print(e)

    print(f"Writing results to: {args.output}")
    with open(args.output, 'w') as f:
        json.dump(breaches, f, indent=2)

    print('Done!')


if __name__ == '__main__':
    main()
