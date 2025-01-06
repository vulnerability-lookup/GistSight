import requests
import re
import time
from datetime import datetime, timezone
from pyvulnerabilitylookup import PyVulnerabilityLookup
from gistsight import config

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
            break

        gists = response.json()
        for gist in gists:
            created_at = parse_utc_datetime(gist.get("created_at"))

            # Safely handle None in description
            description = gist.get("description", "") or ""
            matches_in_description = vulnerability_pattern.findall(description)

            # Check vulnerabilities in gist file contents
            matches_in_files = []
            for file_info in gist.get("files", {}).values():
                file_content = requests.get(file_info["raw_url"], headers=headers).text
                matches_in_files.extend(vulnerability_pattern.findall(file_content))

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
                        "file_name": [
                            file_info["filename"]
                            for file_info in gist.get("files", {}).values()
                        ],
                        "vulnerabilities": list(
                            set(flattened_matches)
                        ),  # Remove duplicates
                        "created_at": created_at,
                    }
                )

        page += 1

    return found_vulnerabilities

def push_sighting_to_vulnerability_lookup(gist_url, timestamp, vulnerability_ids):
    """Create a sighting from an incoming status and push it to the Vulnerability-Lookup instance."""
    print("Pushing sighting to Vulnerability-Lookup…")
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
        }
        print(sighting)

        # Post the JSON to Vulnerability-Lookup
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
            if "message" in r:
                print(r["message"])
        except Exception as e:
            print(
                f"Error when sending POST request to the Vulnerability Lookup server:\n{e}"
            )

def main():
    while True:
        gists = fetch_public_gists()
        if gists:
            for gist in gists:
                print(f"Gist: {gist['gist_url']}")
                print(f"Created At: {gist['created_at'].isoformat()}")
                print(f"Vulnerabilities: {', '.join(gist['vulnerabilities'])}")
                print("-" * 50)

                push_sighting_to_vulnerability_lookup(
                    gist["gist_url"], gist["created_at"], gist["vulnerabilities"]
                )
        else:
            print("No vulnerabilities found.")

        # Wait for 10 seconds before the next execution
        print("Waiting 10 seconds before next run...")
        time.sleep(10)

if __name__ == "__main__":
    main()
