import argparse
import logging
import sys
from typing import Any, Final, Generator
from threading import Thread

import requests
import whois


__all__: Final[tuple[str, ...]] = ()


ICANN_TLD_LIST_URL: Final[str] = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
MAX_DOMAIN_NAME_LENGTH: Final[int] = 63
MIN_DOMAIN_NAME_LENGTH: Final[int] = 1
TARGET_THREADS_TO_START: Final[int] = 15


def _configure_logger(log_level) -> logging.Logger:
    logger = logging.getLogger('domains')
    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def _parse_args():
    parser = argparse.ArgumentParser(description='Set logging level.')
    parser.add_argument('--log-level', type=str, default='INFO', help='Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    return parser.parse_args()


def _fetch_active_tlds() -> list[str]:
    with requests.get(ICANN_TLD_LIST_URL) as resp:
        resp.raise_for_status()
    data_list: list[str] = resp.text.split("\n")
    accurate_of: str = data_list[0].split(",")[1][1::]
    tlds_list: list[str] = data_list[1::]
    logging.info(f"> {len(tlds_list)} TLDs | {accurate_of}")
    return resp.text.split("\n")[1::]


def _fetch_target_domain_name_to_check() -> str:
    domain: str = str(input("What domain name do you wish to mass check the availability of?: "))
    if not MIN_DOMAIN_NAME_LENGTH < len(domain) < MAX_DOMAIN_NAME_LENGTH:
        print(f"[!] Domain must be betwewen {MIN_DOMAIN_NAME_LENGTH} & {MAX_DOMAIN_NAME_LENGTH} characters long.")
        return _fetch_target_domain_name_to_check()
    elif domain.count(".") > 0:
        print(f"[!] Domain must be top-level name only.")
        return _fetch_target_domain_name_to_check()
    return domain


# https://stackoverflow.com/a/312464/17360515
def _chunk_domains(lst: list[str], n: int) -> Generator[list[str], Any, None]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _search(domain_name: str, tlds: list[str]) -> None:
    available_tlds: list[str] = []
    for tld in tlds:
        domain: str = f"{domain_name}.{tld}"
        try:
            result: dict[str, Any] = whois.whois(domain, quiet=True)
        except Exception as e:
            logging.debug(e)  # debug, not error, it happens too much due to private tlds
            continue
        if result.get("registrar") is None:
            continue
        available_tlds.append(tld)
    formatted_tlds: str = ', '.join(available_tlds)
    print(f"{len(available_tlds)} TLD(s) available: {formatted_tlds}.")


def main() -> None:
    target_domain_name: str = _fetch_target_domain_name_to_check()
    tlds: list[str] = _fetch_active_tlds()
    chunk_size: int = len(tlds) // TARGET_THREADS_TO_START
    tld_chunks: list[list[str]] = list(_chunk_domains(tlds, chunk_size))
    logging.info(f"> Starting {len(tld_chunks)} threads searching {len(tlds)} TLDs (~{len(tlds)//len(tld_chunks)} TLDs each).")
    for idx, chunk in enumerate(tld_chunks):
        Thread(target=_search, args=(target_domain_name, chunk)).start()
        logging.info(f"> Started thread {idx + 1}/{len(tld_chunks)}; {len(chunk)} TLDs")


if __name__ == "__main__":
    args = _parse_args()
    _configure_logger(args.log_level)
    main()
