import re
import time
from datetime import datetime

import requests  # type: ignore[import-untyped]
from pyvulnerabilitylookup import PyVulnerabilityLookup

from gistsight import config
from gistsight.monitoring import heartbeat, log

# GitHub API URL
GITHUB_API_URL = config.github_api_url

# Your GitHub personal access token
GITHUB_TOKEN = config.github_token

# Define the vulnerability pattern
vulnerability_pattern = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b"  # CVE pattern
    r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
    r"|\b(PYSEC-\d{4}-\d{2,5})\b"  # PYSEC pattern
    r"|\b(GSD-\d{4}-\d{4,5})\b"  # GSD pattern
    r"|\b(wid-sec-w-\d{4}-\d{4})\b"  # CERT-Bund pattern
    r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"  # CISCO pattern
    r"|\b(RHSA-\d{4}:\d{4})\b",  # RedHat pattern
    re.IGNORECASE,
)


def parse_utc_datetime(date_str):
    """Ensure the input string is parsed into a UTC-aware datetime object."""
    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))


def fetch_public_gists():
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    page = 1
    found_vulnerabilities = []

    while page <= 10:  # Fetch up to 10 pages (adjust as needed)
        response = requests.get(GITHUB_API_URL, headers=headers, params={"page": page})
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            log("error", f"Error in fetch_public_gists: {response.status_code}")
            break

        gists = response.json()
        for gist in gists:
            created_at = parse_utc_datetime(gist.get("created_at"))

            # Safely handle None in description
            description = gist.get("description", "") or ""
            matches_in_description = vulnerability_pattern.findall(description)

            # Check vulnerabilities in gist file contents
            matches_in_files = []
            matched_file_names = []
            matched_file_contents = []
            for file_info in gist.get("files", {}).values():
                file_content = requests.get(file_info["raw_url"], headers=headers).text
                file_matches = vulnerability_pattern.findall(file_content)
                if file_matches:
                    matched_file_names.append(file_info["filename"])
                    matched_file_contents.append(file_content)
                    matches_in_files.extend(file_matches)

            # Combine matches and add to the results if any are found
            all_matches = matches_in_description + matches_in_files

            # Flatten tuples into strings if necessary
            flattened_matches = [
                match if isinstance(match, str) else "".join(filter(None, match))
                for match in all_matches
            ]

            if flattened_matches:
                found_vulnerabilities.append(
                    {
                        "gist_url": gist["html_url"],
                        "file_name": matched_file_names,
                        "file_content": matched_file_contents,
                        "vulnerabilities": list(
                            set(flattened_matches)
                        ),  # Remove duplicates
                        "created_at": created_at,
                    }
                )

        page += 1

    return found_vulnerabilities


def push_sighting_to_vulnerability_lookup(
    gist_url, timestamp, vulnerability_ids, matched_files_content
):
    """Create a sighting from an incoming status and push it to the Vulnerability-Lookup instance."""
    print("Pushing sighting to Vulnerability-Lookup…")
    content = (
        "\n\n".join(matched_files_content)
        if isinstance(matched_files_content, list)
        else str(matched_files_content)
    )
    vuln_lookup = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
    )
    for vuln in vulnerability_ids:
        # Create the sighting

        sighting = {
            "type": "seen",
            "source": gist_url,
            "vulnerability": vuln,
            "creation_timestamp": timestamp,
            "content": content,
        }
        print(sighting)

        # Post the JSON to Vulnerability-Lookup
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
            if "message" in r:
                print(r["message"])
                if "duplicate" in r["message"].lower():
                    level = "info"
                else:
                    level = "warning"
                log(
                    level, f"push_sighting_to_vulnerability_lookup: {r['message']}"
                )
        except Exception as e:
            print(
                f"Error when sending POST request to the Vulnerability-Lookup server:\n{e}"
            )
            log("error", f"Error when sending POST request to the Vulnerability-Lookup server: {e}")


def main():
    while True:
        gists = fetch_public_gists()
        if gists:
            for gist in gists:
                if len(gist["vulnerabilities"]) > config.max_bulk_sighting:
                    # we do not want Gist with plenty of vulnerabilities
                    log("info", "Skipping Gist with too many vulnerability references.")
                    continue
                print(f"Gist: {gist['gist_url']}")
                print(f"Created At: {gist['created_at'].isoformat()}")
                print(f"Vulnerabilities: {', '.join(gist['vulnerabilities'])}")
                print("-" * 50)

                push_sighting_to_vulnerability_lookup(
                    gist["gist_url"],
                    gist["created_at"],
                    gist["vulnerabilities"],
                    gist["file_content"],
                )
        else:
            print("No vulnerabilities found.")

        # Wait for 10 seconds before the next execution
        heartbeat()
        print("Waiting 10 seconds before next run…")
        time.sleep(10)


if __name__ == "__main__":
    main()
