
#!/usr/bin/env python3

"""
Defensive CVE Proof-of-Concept Finder
=====================================

Example usage:

    python3 script.py -o CVE-2024-12345

Optional arguments:

    python3 script.py \
        -o CVE-2024-12345 \
        --minimum-score 60 \
        --maximum-results 30 \
        --json results.json

Optional environment variables:

    GITHUB_TOKEN
        A GitHub personal access token.

        This is not mandatory, but GitHub applies stricter API rate limits
        when requests are made without authentication.

    NVD_API_KEY
        An API key for the National Vulnerability Database.

        This is also optional, but authenticated API requests generally
        receive better rate limits.

What this program does
----------------------

1. Checks that the supplied CVE uses a valid format.
2. Queries NVD to verify that the CVE exists.
3. Extracts relevant references from the NVD CVE record.
4. Searches GitHub for repositories mentioning the exact CVE.
5. Examines repository metadata, README text, and file names.
6. Assigns each candidate a confidence score.
7. Displays only candidates that pass the configured minimum score.

What this program deliberately does not do
------------------------------------------

- It does not clone repositories.
- It does not download exploit files.
- It does not compile any source code.
- It does not execute any proof-of-concept.
- It does not guarantee that a repository is safe.

The scoring system is heuristic. A high score means that several credibility
signals were found, but it does not prove that the code is harmless or genuine.
"""

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------

# argparse handles command-line arguments such as:
#     -o CVE-2024-12345
import argparse

# base64 is used because GitHub returns README file contents in Base64 format.
import base64

# json is used to save results to an optional JSON output file.
import json

# os is used to read environment variables such as GITHUB_TOKEN.
import os

# re provides regular-expression support for validating the CVE format.
import re

# sys is used for:
# - writing error messages to stderr
# - returning an operating-system exit status
import sys

# time is used to add a small delay between unauthenticated GitHub API calls.
import time

# asdict converts a dataclass object into a normal dictionary.
# dataclass provides a clean structure for storing search results.
from dataclasses import asdict, dataclass

# datetime and timezone are used to:
# - calculate repository age
# - add a timestamp to JSON output
from datetime import datetime, timezone

# Path provides convenient file-path handling.
from pathlib import Path

# Any is used in type hints for dictionaries whose values may have
# several different types.
from typing import Any

# urlparse separates a URL into parts such as hostname, path, and scheme.
from urllib.parse import urlparse

# requests is a third-party HTTP library used to call NVD and GitHub APIs.
import requests


# ---------------------------------------------------------------------------
# CVE validation pattern
# ---------------------------------------------------------------------------

# This regular expression accepts CVEs in the following form:
#
#     CVE-2024-1234
#     CVE-2024-12345
#     CVE-2024-1234567
#
# Explanation:
#
#     ^               Start of the string
#     CVE-            Literal text "CVE-"
#     \d{4}           Exactly four digits for the year
#     -               Literal hyphen
#     \d{4,7}         Between four and seven digits for the CVE number
#     $               End of the string
#
# re.IGNORECASE allows values such as:
#
#     cve-2024-12345
#
# The program later converts them to uppercase.
CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,7}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# External API URLs
# ---------------------------------------------------------------------------

# NVD CVE API endpoint.
#
# The program sends a request such as:
#
#     https://services.nvd.nist.gov/rest/json/cves/2.0
#         ?cveId=CVE-2024-12345
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Base URL for GitHub's REST API.
GITHUB_API_URL = "https://api.github.com"


# ---------------------------------------------------------------------------
# Trusted reference domains
# ---------------------------------------------------------------------------

# Only NVD references from these domains are treated as useful PoC or
# security-research candidates.
#
# This is an allowlist rather than a blocklist.
#
# An allowlist is safer because unknown domains are rejected by default.
# However, it may also exclude legitimate research hosted elsewhere.
TRUSTED_REFERENCE_DOMAINS = {
    "github.com",
    "gitlab.com",
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "securityfocus.com",
    "seclists.org",
    "project-zero.issues.chromium.org",
    "googleprojectzero.github.io",
    "securitylab.github.com",
    "blog.talosintelligence.com",
    "talosintelligence.com",
    "zerodayinitiative.com",
    "www.zerodayinitiative.com",
    "rapid7.com",
    "www.rapid7.com",
    "metasploit.com",
    "www.metasploit.com",
}


# ---------------------------------------------------------------------------
# Recognised GitHub security-research accounts
# ---------------------------------------------------------------------------

# Repositories belonging to these owners receive additional confidence points.
#
# Important:
#
# This does not mean that every repository belonging to these accounts is
# automatically safe. It only provides one additional trust indicator.
#
# GitHub usernames are converted to lowercase before comparison.
TRUSTED_GITHUB_OWNERS = {
    "rapid7",
    "googleprojectzero",
    "github",
    "githubsecuritylab",
    "projectdiscovery",
    "nuclei-templates",
    "oss-fuzz",
    "pwntester",
    "assetnote",
    "watchtowrlabs",
    "bishopfox",
    "trailofbits",
    "thezdi",
    "0xdea",
    "fortra",
    "horizon3ai",
    "vulhub",
}


# ---------------------------------------------------------------------------
# Suspicious phrases
# ---------------------------------------------------------------------------

# If these phrases appear in a repository name, description, or README,
# the repository receives a large score penalty.
#
# These terms may indicate malware, credential theft, evasion, or other
# unrelated and potentially harmful content.
#
# This check is not perfect:
#
# - A legitimate security analysis may mention one of these terms.
# - Malicious repositories may avoid using obvious suspicious terminology.
SUSPICIOUS_TERMS = {
    "fud",
    "fully undetected",
    "cryptor",
    "stealer",
    "ransomware",
    "botnet",
    "miner",
    "crypter",
    "bypass antivirus",
    "disable defender",
    "persistence",
    "token grabber",
    "credential stealer",
}


# ---------------------------------------------------------------------------
# Proof-of-concept terminology
# ---------------------------------------------------------------------------

# The presence of these phrases may indicate that a repository contains
# a reproduction or proof-of-concept rather than only a copied advisory.
POC_TERMS = {
    "proof of concept",
    "proof-of-concept",
    "poc",
    "exploit",
    "reproducer",
    "reproduction",
    "trigger",
    "vulnerability",
}


# ---------------------------------------------------------------------------
# Recognised source and reproduction file extensions
# ---------------------------------------------------------------------------

# The program examines the GitHub repository file tree.
#
# If it finds files with these extensions, the repository receives additional
# points because it appears to contain actual source code or test material.
#
# The program only inspects file names through the API. It does not download
# the files themselves.
CODE_EXTENSIONS = {
    ".py",     # Python
    ".go",     # Go
    ".c",      # C
    ".cc",     # C++
    ".cpp",    # C++
    ".cs",     # C#
    ".java",   # Java
    ".js",     # JavaScript
    ".ts",     # TypeScript
    ".rb",     # Ruby
    ".rs",     # Rust
    ".php",    # PHP
    ".sh",     # Shell script
    ".ps1",    # PowerShell
    ".html",   # HTML reproduction page
    ".yaml",   # YAML, possibly a Nuclei template
    ".yml",    # YAML, alternate extension
}


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class ResearchError(RuntimeError):
    """
    Exception used for expected API or research-related failures.

    Examples include:

    - Network connection failure
    - API rate limit reached
    - Invalid JSON response
    - Resource not found
    - CVE missing from NVD

    Using a custom exception makes it easier for the main function to
    distinguish expected research errors from programming errors.
    """


# ---------------------------------------------------------------------------
# Candidate result structure
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """
    Represents one possible PoC or technical reference.

    Attributes
    ----------

    source:
        Where the result came from.

        Examples:
            "GitHub"
            "NVD reference"

    title:
        Human-readable result title.

        For GitHub results, this is normally:
            owner/repository-name

    url:
        Direct URL to the result.

    score:
        Heuristic trust score between 0 and 100.

    confidence:
        Text label calculated from the score.

        Possible values:
            high
            moderate
            low
            untrusted

    reasons:
        Positive indicators that increased the score.

    warnings:
        Negative indicators or concerns that reduced the score.

    owner:
        GitHub repository owner.

        This is None for non-GitHub results.

    stars:
        Number of GitHub stars.

    forks:
        Number of GitHub forks.

    updated_at:
        Repository's latest GitHub update timestamp.

    archived:
        Whether the GitHub repository has been archived.

    description:
        GitHub repository description.
    """

    source: str
    title: str
    url: str
    score: int
    confidence: str
    reasons: list[str]
    warnings: list[str]

    # The following fields are optional because an NVD reference may not
    # have GitHub-specific metadata.
    owner: str | None = None
    stars: int | None = None
    forks: int | None = None
    updated_at: str | None = None
    archived: bool | None = None
    description: str | None = None


# ---------------------------------------------------------------------------
# General HTTP request helper
# ---------------------------------------------------------------------------

def request_json(
    session: requests.Session,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    """
    Send an HTTP GET request and return the response as a dictionary.

    Parameters
    ----------

    session:
        A requests.Session object.

        Reusing a session allows HTTP connections to be reused, which is
        more efficient than creating a completely new connection for every
        API request.

    url:
        API endpoint being requested.

    params:
        Optional query-string parameters.

        Example:
            {"cveId": "CVE-2024-12345"}

    headers:
        Optional HTTP headers.

        Examples include:
            Authorization
            User-Agent
            Accept

    timeout:
        Maximum number of seconds to wait for a response.

    Returns
    -------

    dict[str, Any]:
        Decoded JSON response.

    Raises
    ------

    ResearchError:
        Raised if the request fails, the API returns an error, or the
        response is not valid JSON.
    """

    try:
        # session.get sends an HTTP GET request.
        response = session.get(
            url,

            # Query-string parameters such as ?cveId=CVE-2024-12345.
            params=params,

            # API headers such as authentication tokens.
            headers=headers,

            # Prevent the program from waiting indefinitely.
            timeout=timeout,

            # Permit normal HTTP redirects.
            allow_redirects=True,
        )

    except requests.RequestException as exc:
        # requests.RequestException is the parent exception for most
        # requests-related failures, such as:
        #
        # - connection failure
        # - timeout
        # - invalid URL
        #
        # "raise ... from exc" keeps the original exception as the cause.
        raise ResearchError(
            f"Request failed for {url}: {exc}"
        ) from exc

    # GitHub commonly returns HTTP 403 when the API rate limit is exceeded.
    #
    # We check both the status code and response body to avoid treating every
    # possible 403 response as a rate-limit issue.
    if (
        response.status_code == 403
        and "rate limit" in response.text.lower()
    ):
        raise ResearchError(
            "API rate limit reached. "
            "Set GITHUB_TOKEN or NVD_API_KEY and retry."
        )

    # HTTP 404 means that the requested API resource was not found.
    if response.status_code == 404:
        raise ResearchError(
            f"Resource not found: {url}"
        )

    try:
        # raise_for_status raises an HTTPError for response codes such as:
        #
        # - 400 Bad Request
        # - 401 Unauthorized
        # - 403 Forbidden
        # - 500 Internal Server Error
        response.raise_for_status()

    except requests.HTTPError as exc:
        # Only include the first 300 characters of the response body.
        #
        # This keeps the error readable and avoids printing a potentially
        # very large HTML or JSON error response.
        body = response.text[:300].replace("\n", " ")

        raise ResearchError(
            f"HTTP {response.status_code} from {url}: {body}"
        ) from exc

    try:
        # Convert the response body from JSON text into Python objects.
        result = response.json()

    except ValueError as exc:
        # response.json raises ValueError when the response is not valid JSON.
        raise ResearchError(
            f"Invalid JSON returned by {url}"
        ) from exc

    # The program expects the top-level JSON object to be a dictionary.
    #
    # A list or another value would not match the expected NVD/GitHub
    # response structure.
    if not isinstance(result, dict):
        raise ResearchError(
            f"Unexpected response format from {url}"
        )

    return result


# ---------------------------------------------------------------------------
# CVE command-line validation
# ---------------------------------------------------------------------------

def validate_cve(value: str) -> str:
    """
    Validate and normalise a CVE supplied through the command line.

    Example input:
        cve-2024-12345

    Returned value:
        CVE-2024-12345

    argparse automatically displays the raised error message if validation
    fails.
    """

    # Remove leading/trailing spaces and convert the value to uppercase.
    cve = value.strip().upper()

    # fullmatch requires the entire value to match CVE_PATTERN.
    #
    # This prevents partial matches such as:
    #
    #     CVE-2024-12345-malicious-text
    if not CVE_PATTERN.fullmatch(cve):
        raise argparse.ArgumentTypeError(
            "CVE must use the format CVE-YYYY-NNNN, "
            "for example CVE-2024-12345."
        )

    return cve


# ---------------------------------------------------------------------------
# URL hostname extraction
# ---------------------------------------------------------------------------

def hostname(url: str) -> str:
    """
    Extract and normalise the hostname from a URL.

    Example:

        Input:
            https://www.Exploit-DB.com/exploits/12345

        Output:
            www.exploit-db.com

    An empty string is returned if the URL cannot be parsed.
    """

    try:
        # urlparse(url).hostname extracts only the domain name.
        #
        # "or ''" handles URLs with no hostname.
        host = urlparse(url).hostname or ""

        # Convert the domain to lowercase and remove a trailing dot.
        return host.lower().rstrip(".")

    except ValueError:
        # Some malformed URLs may cause urlparse to raise ValueError.
        return ""


# ---------------------------------------------------------------------------
# Trusted-domain check
# ---------------------------------------------------------------------------

def is_trusted_reference(url: str) -> bool:
    """
    Check whether a URL belongs to an allowlisted domain.

    Subdomains are accepted.

    For example, if the allowlist contains:

        example.com

    Then both of these are accepted:

        example.com
        research.example.com

    But this is rejected:

        example.com.attacker-site.test
    """

    host = hostname(url)

    return any(
        # Exact domain match.
        host == domain

        # Proper subdomain match.
        or host.endswith("." + domain)

        for domain in TRUSTED_REFERENCE_DOMAINS
    )


# ---------------------------------------------------------------------------
# CVE description extraction
# ---------------------------------------------------------------------------

def get_english_description(
    cve_data: dict[str, Any],
) -> str:
    """
    Extract the English description from an NVD CVE record.

    NVD may provide descriptions in multiple languages.

    A simplified structure may look like:

        {
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A vulnerability exists..."
                },
                {
                    "lang": "es",
                    "value": "Existe una vulnerabilidad..."
                }
            ]
        }
    """

    descriptions = cve_data.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return str(
                item.get("value", "")
            ).strip()

    # Return an empty string if no English description is available.
    return ""


# ---------------------------------------------------------------------------
# NVD CVE lookup
# ---------------------------------------------------------------------------

def fetch_nvd_record(
    session: requests.Session,
    cve: str,
    nvd_api_key: str | None,
) -> dict[str, Any]:
    """
    Retrieve one CVE record from NVD.

    The CVE format may be valid even if the identifier does not exist.
    Therefore, checking NVD helps filter random or mistyped CVE identifiers.
    """

    # Headers sent with the NVD API request.
    headers = {
        # Identifies the application making the request.
        "User-Agent": "Defensive-CVE-PoC-Finder/1.0",

        # Tells the server that the program expects JSON.
        "Accept": "application/json",
    }

    # Add the NVD API key only when one was supplied.
    #
    # This avoids sending an empty or invalid apiKey header.
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    # Request CVE data from NVD.
    data = request_json(
        session,
        NVD_API_URL,
        params={
            "cveId": cve,
        },
        headers=headers,
    )

    # NVD places matching records inside the "vulnerabilities" array.
    vulnerabilities = data.get("vulnerabilities", [])

    # An empty list means NVD did not return a matching CVE record.
    if not vulnerabilities:
        raise ResearchError(
            f"{cve} was not found in NVD. "
            "It may be invalid, rejected, reserved, "
            "or not yet indexed."
        )

    # The NVD response normally looks approximately like:
    #
    # {
    #     "vulnerabilities": [
    #         {
    #             "cve": {
    #                 ...
    #             }
    #         }
    #     ]
    # }
    #
    # Since the query requested one exact CVE, use the first result.
    return vulnerabilities[0].get("cve", {})


# ---------------------------------------------------------------------------
# NVD reference processing
# ---------------------------------------------------------------------------

def extract_nvd_candidates(
    cve: str,
    record: dict[str, Any],
) -> list[Candidate]:
    """
    Convert suitable NVD references into Candidate objects.

    NVD records may contain:

    - Vendor advisories
    - Patches
    - Technical analyses
    - Exploit references
    - Mailing-list discussions
    - Issue trackers

    Only references from allowlisted domains are retained.
    """

    candidates: list[Candidate] = []

    # Go through every reference attached to the NVD record.
    for reference in record.get("references", []):
        # Extract and clean the reference URL.
        url = str(
            reference.get("url", "")
        ).strip()

        # NVD may attach labels such as:
        #
        # - Exploit
        # - Vendor Advisory
        # - Technical Description
        # - Patch
        tags = [
            str(tag)
            for tag in reference.get("tags", [])
        ]

        # Skip missing URLs and non-allowlisted domains.
        if not url or not is_trusted_reference(url):
            continue

        # Every trusted NVD reference begins with a base score.
        score = 35

        # Positive scoring explanations.
        reasons = [
            "Referenced by the official NVD CVE record",
        ]

        # There are initially no warnings for the reference.
        warnings: list[str] = []

        # Convert tags to lowercase for case-insensitive comparisons.
        lowered_tags = {
            tag.lower()
            for tag in tags
        }

        # NVD explicitly identifying a link as an exploit is a strong signal.
        if "exploit" in lowered_tags:
            score += 30
            reasons.append(
                "NVD labels the reference as an exploit"
            )

        # A technical description may contain reproduction details.
        if "technical description" in lowered_tags:
            score += 10
            reasons.append(
                "NVD labels it as a technical description"
            )

        # Vendor advisories are credible primary references, although they may
        # not contain working proof-of-concept code.
        if "vendor advisory" in lowered_tags:
            score += 10
            reasons.append(
                "NVD labels it as a vendor advisory"
            )

        # Extract the reference's hostname for source-specific scoring.
        host = hostname(url)

        # Exploit-DB is a curated public exploit database, so references
        # hosted there receive additional points.
        if host in {
            "exploit-db.com",
            "www.exploit-db.com",
        }:
            score += 15
            reasons.append(
                "Hosted by Exploit-DB"
            )

        # GitHub hosting is useful because source history and repository
        # metadata are usually available for manual inspection.
        if host == "github.com":
            score += 5
            reasons.append(
                "Hosted on GitHub"
            )

        # Ensure that the score cannot exceed 100.
        final_score = min(score, 100)

        candidates.append(
            Candidate(
                source="NVD reference",
                title=f"{cve} reference on {host}",
                url=url,
                score=final_score,
                confidence=confidence_label(final_score),
                reasons=reasons,
                warnings=warnings,
            )
        )

    return candidates


# ---------------------------------------------------------------------------
# GitHub API headers
# ---------------------------------------------------------------------------

def github_headers(
    token: str | None,
) -> dict[str, str]:
    """
    Build the HTTP headers used for GitHub API requests.

    The GitHub token is optional.

    Without a token, GitHub normally permits fewer API requests per hour.
    """

    headers = {
        # Request GitHub's recommended JSON response format.
        "Accept": "application/vnd.github+json",

        # Identify the script making the request.
        "User-Agent": "Defensive-CVE-PoC-Finder/1.0",

        # Select a stable version of the GitHub REST API.
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Include authentication only if the user set GITHUB_TOKEN.
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


# ---------------------------------------------------------------------------
# GitHub README retrieval
# ---------------------------------------------------------------------------

def fetch_repository_readme(
    session: requests.Session,
    full_name: str,
    headers: dict[str, str],
) -> str:
    """
    Retrieve and decode a repository's README.

    GitHub returns README content encoded in Base64.

    Parameters
    ----------

    full_name:
        Repository in owner/name format.

        Example:
            rapid7/metasploit-framework

    Returns
    -------

    str:
        Decoded README text.

        An empty string is returned if:
        - no README exists
        - the request fails
        - the encoding is unsupported
        - the content cannot be decoded
    """

    try:
        data = request_json(
            session,
            f"{GITHUB_API_URL}/repos/{full_name}/readme",
            headers=headers,
        )

    except ResearchError:
        # A missing README should not stop the entire search.
        return ""

    # GitHub returns file content in the "content" field.
    encoded = data.get("content")

    # The "encoding" field should normally contain "base64".
    encoding = data.get("encoding")

    # Stop if the expected fields are absent.
    if not encoded or encoding != "base64":
        return ""

    try:
        # Convert Base64 data into raw bytes.
        decoded = base64.b64decode(
            encoded,
            validate=False,
        )

        # Convert bytes into readable UTF-8 text.
        #
        # errors="replace" prevents decoding from failing completely if the
        # README contains invalid byte sequences.
        text = decoded.decode(
            "utf-8",
            errors="replace",
        )

        # Limit processing to 100,000 characters.
        #
        # Extremely large README files are unnecessary for this analysis
        # and could consume excessive memory or processing time.
        return text[:100_000]

    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# GitHub repository file-tree inspection
# ---------------------------------------------------------------------------

def repository_has_code_files(
    session: requests.Session,
    full_name: str,
    default_branch: str,
    headers: dict[str, str],
) -> tuple[bool, list[str]]:
    """
    Inspect repository file names without downloading repository files.

    The GitHub Git Trees API returns a repository's directory and file
    structure.

    Returns
    -------

    tuple[bool, list[str]]

    First value:
        True if recognised source/reproduction files were found.

    Second value:
        Up to ten matching file paths.
    """

    try:
        tree = request_json(
            session,

            # The branch name can be used as the tree reference.
            f"{GITHUB_API_URL}/repos/"
            f"{full_name}/git/trees/{default_branch}",

            # recursive=1 requests the full nested file tree.
            params={
                "recursive": "1",
            },

            headers=headers,
        )

    except ResearchError:
        # Repository trees may fail to load for several reasons:
        #
        # - repository unavailable
        # - empty repository
        # - branch missing
        # - API limitation
        #
        # Treat this as "no recognised files found" instead of terminating.
        return False, []

    matching_files: list[str] = []

    # The "tree" array contains both directories and files.
    for item in tree.get("tree", []):
        # GitHub describes normal files as "blob".
        #
        # Directories are usually "tree".
        if item.get("type") != "blob":
            continue

        # Obtain the file path.
        path = str(
            item.get("path", "")
        )

        # Extract the lowercase file extension.
        #
        # Example:
        #     exploit.PY -> .py
        extension = Path(
            path.lower()
        ).suffix

        # Retain files using recognised source-code extensions.
        if extension in CODE_EXTENSIONS:
            matching_files.append(path)

        # Ten examples are enough for scoring and display.
        #
        # There is no need to collect thousands of source-file names.
        if len(matching_files) >= 10:
            break

    return bool(matching_files), matching_files


# ---------------------------------------------------------------------------
# Repository age calculation
# ---------------------------------------------------------------------------

def days_since(
    date_string: str | None,
) -> int | None:
    """
    Calculate the number of days since an ISO-formatted timestamp.

    Example GitHub timestamp:

        2026-07-20T10:15:30Z

    Returns None if the value is missing or invalid.
    """

    if not date_string:
        return None

    try:
        # Python's fromisoformat expects a UTC offset such as +00:00.
        #
        # GitHub commonly represents UTC with a trailing Z, so replace:
        #
        #     Z
        #
        # with:
        #
        #     +00:00
        parsed = datetime.fromisoformat(
            date_string.replace("Z", "+00:00")
        )

        # Get the current UTC time.
        now = datetime.now(timezone.utc)

        # Calculate the difference in whole days.
        #
        # max(0, ...) avoids returning a negative result if a timestamp is
        # slightly ahead because of clock differences.
        return max(
            0,
            (now - parsed).days,
        )

    except ValueError:
        return None


# ---------------------------------------------------------------------------
# GitHub repository scoring
# ---------------------------------------------------------------------------

def score_github_repository(
    cve: str,
    repository: dict[str, Any],
    readme: str,
    code_files: list[str],
) -> Candidate:
    """
    Calculate a heuristic confidence score for one GitHub repository.

    Positive indicators include:

    - Exact CVE in the repository name
    - Exact CVE in the description
    - Exact CVE in the README
    - PoC-related terminology
    - Source or reproduction files
    - Recognised security-research owner
    - Community activity such as stars and forks
    - Repository older than 30 days

    Negative indicators include:

    - CVE missing from README
    - No recognised source files
    - Zero stars
    - Repository created extremely recently
    - Archived repository
    - Forked repository
    - Empty repository
    - Suspicious terminology

    This score is not a malware-analysis result and must not be treated as
    proof that the repository is safe.
    """

    # GitHub repository name in owner/repository format.
    full_name = str(
        repository.get(
            "full_name",
            "unknown/unknown",
        )
    )

    # Repository owner login.
    owner = str(
        repository.get(
            "owner",
            {},
        ).get(
            "login",
            "",
        )
    )

    # Repository description may be None, so "or ''" converts it to an
    # empty string.
    description = str(
        repository.get("description") or ""
    )

    # Public GitHub URL.
    html_url = str(
        repository.get("html_url", "")
    )

    # Convert numeric metadata to integers.
    #
    # "or 0" handles null values.
    stars = int(
        repository.get(
            "stargazers_count",
            0,
        ) or 0
    )

    forks = int(
        repository.get(
            "forks_count",
            0,
        ) or 0
    )

    # Convert Boolean metadata safely.
    archived = bool(
        repository.get(
            "archived",
            False,
        )
    )

    fork = bool(
        repository.get(
            "fork",
            False,
        )
    )

    # Repository update and creation timestamps.
    updated_at = repository.get("updated_at")
    created_at = repository.get("created_at")

    # GitHub reports repository size in kilobytes.
    size = int(
        repository.get(
            "size",
            0,
        ) or 0
    )

    # Combine searchable textual fields and convert them to lowercase.
    #
    # This allows case-insensitive term searches.
    combined_text = (
        f"{full_name}\n"
        f"{description}\n"
        f"{readme}"
    ).lower()

    # Lowercase version of the requested CVE.
    cve_lower = cve.lower()

    # Start from a neutral score.
    score = 0

    # Store explanations for positive and negative decisions.
    reasons: list[str] = []
    warnings: list[str] = []

    # -----------------------------------------------------------------------
    # CVE in repository name
    # -----------------------------------------------------------------------

    # Repositories specifically created for one vulnerability often include
    # the CVE identifier in the repository name.
    if cve_lower in full_name.lower():
        score += 25
        reasons.append(
            "Exact CVE appears in the repository name"
        )

    # -----------------------------------------------------------------------
    # CVE in description
    # -----------------------------------------------------------------------

    if cve_lower in description.lower():
        score += 15
        reasons.append(
            "Exact CVE appears in the repository description"
        )

    # -----------------------------------------------------------------------
    # CVE in README
    # -----------------------------------------------------------------------

    if cve_lower in readme.lower():
        score += 20
        reasons.append(
            "Exact CVE appears in the README"
        )
    else:
        # A repository may appear in search results because of metadata,
        # forks, or weak text matching. Missing CVE evidence in the README
        # lowers confidence.
        score -= 20
        warnings.append(
            "Exact CVE was not found in the README"
        )

    # -----------------------------------------------------------------------
    # PoC-related terminology
    # -----------------------------------------------------------------------

    # Find every proof-of-concept term appearing in the repository text.
    matched_poc_terms = sorted(
        term
        for term in POC_TERMS
        if term in combined_text
    )

    if matched_poc_terms:
        score += 10

        # Display no more than three terms to keep output readable.
        reasons.append(
            "PoC-related terminology found: "
            + ", ".join(matched_poc_terms[:3])
        )

    # -----------------------------------------------------------------------
    # Source or reproduction files
    # -----------------------------------------------------------------------

    if code_files:
        score += 15

        reasons.append(
            "Repository contains source/reproduction files: "
            + ", ".join(code_files[:3])
        )
    else:
        score -= 15

        warnings.append(
            "No recognised source or reproduction files found"
        )

    # -----------------------------------------------------------------------
    # Recognised repository owner
    # -----------------------------------------------------------------------

    if owner.lower() in TRUSTED_GITHUB_OWNERS:
        score += 25

        reasons.append(
            "Published by a recognised security-research owner"
        )

    # -----------------------------------------------------------------------
    # GitHub star scoring
    # -----------------------------------------------------------------------

    # Stars do not prove correctness or safety.
    #
    # They are only used as a small community-interest signal.
    if stars >= 100:
        score += 12
        reasons.append(
            f"Repository has {stars} stars"
        )

    elif stars >= 20:
        score += 8
        reasons.append(
            f"Repository has {stars} stars"
        )

    elif stars >= 5:
        score += 4
        reasons.append(
            f"Repository has {stars} stars"
        )

    elif stars == 0:
        score -= 3
        warnings.append(
            "Repository has no stars"
        )

    # -----------------------------------------------------------------------
    # GitHub fork scoring
    # -----------------------------------------------------------------------

    if forks >= 10:
        score += 5

        reasons.append(
            f"Repository has {forks} forks"
        )

    # -----------------------------------------------------------------------
    # Repository age scoring
    # -----------------------------------------------------------------------

    age = days_since(created_at)

    # A repository older than 30 days receives a small positive score.
    #
    # This does not make it safe, but it reduces confidence in repositories
    # created immediately after a CVE becomes popular.
    if age is not None and age >= 30:
        score += 3

        reasons.append(
            "Repository is older than 30 days"
        )

    # A repository created within the last two days receives a penalty.
    elif age is not None and age <= 2:
        score -= 8

        warnings.append(
            "Repository was created very recently"
        )

    # -----------------------------------------------------------------------
    # Archived repository
    # -----------------------------------------------------------------------

    if archived:
        score -= 5

        warnings.append(
            "Repository is archived"
        )

    # -----------------------------------------------------------------------
    # Forked repository
    # -----------------------------------------------------------------------

    # Forks can be legitimate, but original repositories are generally easier
    # to attribute and inspect.
    if fork:
        score -= 5

        warnings.append(
            "Repository is a fork"
        )

    # -----------------------------------------------------------------------
    # Empty repository
    # -----------------------------------------------------------------------

    if size == 0:
        score -= 20

        warnings.append(
            "Repository appears empty"
        )

    # -----------------------------------------------------------------------
    # Suspicious terminology
    # -----------------------------------------------------------------------

    suspicious_found = sorted(
        term
        for term in SUSPICIOUS_TERMS
        if term in combined_text
    )

    if suspicious_found:
        # Apply a large penalty because these phrases may indicate that the
        # repository contains malware or unrelated offensive tooling.
        score -= 50

        warnings.append(
            "Suspicious terminology found: "
            + ", ".join(suspicious_found[:4])
        )

    # Keep the final score between 0 and 100.
    score = max(
        0,
        min(score, 100),
    )

    # Return all collected information as a Candidate object.
    return Candidate(
        source="GitHub",
        title=full_name,
        url=html_url,
        score=score,
        confidence=confidence_label(score),
        reasons=reasons,
        warnings=warnings,
        owner=owner,
        stars=stars,
        forks=forks,
        updated_at=updated_at,
        archived=archived,
        description=description or None,
    )


# ---------------------------------------------------------------------------
# GitHub search
# ---------------------------------------------------------------------------

def search_github(
    session: requests.Session,
    cve: str,
    token: str | None,
    maximum_results: int,
) -> list[Candidate]:
    """
    Search GitHub repositories for the exact CVE identifier.

    Each returned repository is further inspected by:

    - retrieving its README
    - inspecting its file tree
    - calculating a confidence score
    """

    # Build GitHub API headers, optionally including authentication.
    headers = github_headers(token)

    # GitHub repository-search query.
    #
    # The double quotation marks request the exact CVE phrase.
    #
    # in:name,description,readme tells GitHub to search:
    #
    # - repository name
    # - repository description
    # - README content
    query = f'"{cve}" in:name,description,readme'

    # Search GitHub repositories.
    data = request_json(
        session,
        f"{GITHUB_API_URL}/search/repositories",
        params={
            # Search query.
            "q": query,

            # Ask GitHub to sort by stars.
            "sort": "stars",

            # Highest-star repositories first.
            "order": "desc",

            # GitHub allows a maximum of 100 results per page.
            "per_page": min(maximum_results, 100),
        },
        headers=headers,
    )

    candidates: list[Candidate] = []

    # Process up to maximum_results repositories.
    for repository in data.get(
        "items",
        [],
    )[:maximum_results]:

        # Repository name in owner/repository format.
        full_name = str(
            repository.get(
                "full_name",
                "",
            )
        )

        # Default branch is commonly "main" or "master".
        #
        # Use "main" as a fallback if GitHub does not supply the value.
        default_branch = str(
            repository.get(
                "default_branch",
                "main",
            )
        )

        # Skip malformed results without a repository name.
        if not full_name:
            continue

        # Retrieve README text.
        readme = fetch_repository_readme(
            session,
            full_name,
            headers,
        )

        # Inspect repository file names.
        #
        # The first tuple value is not needed here because code_files itself
        # can be checked as true or false.
        _, code_files = repository_has_code_files(
            session,
            full_name,
            default_branch,
            headers,
        )

        # Calculate a trust score for the repository.
        candidate = score_github_repository(
            cve,
            repository,
            readme,
            code_files,
        )

        candidates.append(candidate)

        # Unauthenticated GitHub API limits are stricter.
        #
        # A short delay helps avoid sending a rapid burst of requests.
        if not token:
            time.sleep(0.15)

    return candidates


# ---------------------------------------------------------------------------
# Confidence label conversion
# ---------------------------------------------------------------------------

def confidence_label(score: int) -> str:
    """
    Convert a numeric score into a human-readable confidence level.

    Score ranges:

        80-100  high
        60-79   moderate
        40-59   low
        0-39    untrusted
    """

    if score >= 80:
        return "high"

    if score >= 60:
        return "moderate"

    if score >= 40:
        return "low"

    return "untrusted"


# ---------------------------------------------------------------------------
# Duplicate-result removal
# ---------------------------------------------------------------------------

def deduplicate(
    candidates: list[Candidate],
) -> list[Candidate]:
    """
    Remove duplicate URLs.

    The same link might appear in both:

    - NVD references
    - GitHub search results

    When two candidates have the same URL, retain the one with the
    higher confidence score.
    """

    # Dictionary mapping:
    #
    #     normalised URL -> selected Candidate
    selected: dict[str, Candidate] = {}

    for candidate in candidates:
        # Normalise the URL so these are treated as equal:
        #
        #     https://github.com/example/repo
        #     https://github.com/example/repo/
        #
        # Lowercasing also avoids case differences.
        normalized_url = (
            candidate.url
            .rstrip("/")
            .lower()
        )

        # Check whether this URL has already been seen.
        existing = selected.get(normalized_url)

        # Keep the new candidate if:
        #
        # - the URL has not appeared before, or
        # - this candidate has a higher score
        if (
            existing is None
            or candidate.score > existing.score
        ):
            selected[normalized_url] = candidate

    # Convert the dictionary values back into a list.
    return list(selected.values())


# ---------------------------------------------------------------------------
# Terminal output formatting
# ---------------------------------------------------------------------------

def print_candidate(
    candidate: Candidate,
    position: int,
) -> None:
    """
    Print one candidate in a readable terminal format.
    """

    print(
        f"\n[{position}] {candidate.title}"
    )

    print(
        f"    Source:     {candidate.source}"
    )

    print(
        f"    Confidence: {candidate.confidence}"
    )

    print(
        f"    Score:      {candidate.score}/100"
    )

    print(
        f"    URL:        {candidate.url}"
    )

    # Only print the description when one is available.
    if candidate.description:
        print(
            f"    Description: {candidate.description}"
        )

    # GitHub results contain owner information.
    #
    # NVD-only references normally do not.
    if candidate.owner:
        print(
            "    GitHub: "
            f"owner={candidate.owner}, "
            f"stars={candidate.stars}, "
            f"forks={candidate.forks}, "
            f"updated={candidate.updated_at}"
        )

    # Print positive scoring reasons.
    for reason in candidate.reasons:
        print(
            f"    [+] {reason}"
        )

    # Print warnings and negative indicators.
    for warning in candidate.warnings:
        print(
            f"    [!] {warning}"
        )


# ---------------------------------------------------------------------------
# Command-line argument definitions
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Define and parse the program's command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Find and rank publicly available CVE "
            "proof-of-concept references without "
            "downloading or executing them."
        )
    )

    # Required CVE argument.
    #
    # Both of these forms are accepted:
    #
    #     -o CVE-2024-12345
    #     --cve CVE-2024-12345
    parser.add_argument(
        "-o",
        "--cve",
        required=True,

        # argparse passes the supplied value through validate_cve.
        type=validate_cve,

        help=(
            "CVE identifier, for example "
            "CVE-2024-12345"
        ),
    )

    # Minimum score required for a result to be displayed.
    parser.add_argument(
        "--minimum-score",

        # Convert command-line text into an integer.
        type=int,

        # Default threshold.
        default=50,

        # Restrict the value to 0 through 100.
        choices=range(0, 101),

        # Text shown in the usage message.
        metavar="0-100",

        help=(
            "Only show candidates at or above "
            "this score (default: 50)"
        ),
    )

    # Maximum number of GitHub repositories to inspect.
    parser.add_argument(
        "--maximum-results",
        type=int,
        default=20,

        # Permit values from 1 through 100.
        choices=range(1, 101),
        metavar="1-100",

        help=(
            "Maximum GitHub repositories to inspect "
            "(default: 20)"
        ),
    )

    # Optional JSON output path.
    parser.add_argument(
        "--json",

        # Store the command-line value in args.json_file.
        dest="json_file",

        help=(
            "Optionally save the complete result as JSON"
        ),
    )

    # Parse sys.argv and return the resulting Namespace object.
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main program workflow
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Run the complete CVE lookup and scoring workflow.

    Return values
    -------------

    0:
        Program completed successfully.

    1:
        An error prevented successful completion.
    """

    # Read command-line arguments.
    args = parse_arguments()

    # Read optional API credentials from environment variables.
    github_token = os.environ.get(
        "GITHUB_TOKEN"
    )

    nvd_api_key = os.environ.get(
        "NVD_API_KEY"
    )

    # Create one reusable HTTP session.
    session = requests.Session()

    print(
        f"[*] Checking {args.cve} against NVD..."
    )

    try:
        # Verify the CVE and retrieve its NVD information.
        nvd_record = fetch_nvd_record(
            session,
            args.cve,
            nvd_api_key,
        )

    except ResearchError as exc:
        # Print errors to stderr rather than normal stdout.
        print(
            f"[ERROR] {exc}",
            file=sys.stderr,
        )

        # Exit with failure status.
        return 1

    # NVD statuses may include values such as:
    #
    # - Analyzed
    # - Modified
    # - Awaiting Analysis
    # - Rejected
    # - Reserved
    status = str(
        nvd_record.get(
            "vulnStatus",
            "Unknown",
        )
    )

    # Extract a readable English description.
    description = get_english_description(
        nvd_record
    )

    print(
        f"[+] CVE status: {status}"
    )

    if description:
        print(
            f"[+] Description: {description}"
        )

    # Reserved or rejected CVEs require caution.
    #
    # A rejected CVE may have been withdrawn because it was invalid,
    # duplicated, or otherwise unsuitable.
    #
    # A reserved CVE may not yet contain complete public information.
    if status.lower() in {
        "rejected",
        "reserved",
    }:
        print(
            f"[!] The NVD status is {status}. "
            "PoC results may be invalid or mislabelled.",
            file=sys.stderr,
        )

    # Begin with candidates extracted from NVD references.
    all_candidates = extract_nvd_candidates(
        args.cve,
        nvd_record,
    )

    print(
        "[*] Inspecting GitHub repository metadata..."
    )

    try:
        # Search GitHub and add the returned candidates to the existing list.
        all_candidates.extend(
            search_github(
                session,
                args.cve,
                github_token,
                args.maximum_results,
            )
        )

    except ResearchError as exc:
        # A GitHub failure does not invalidate the NVD results.
        #
        # Therefore, print a warning and continue.
        print(
            f"[WARNING] GitHub search failed: {exc}",
            file=sys.stderr,
        )

    # Remove duplicate URLs.
    all_candidates = deduplicate(
        all_candidates
    )

    # Sort results from highest score to lowest.
    #
    # If scores are equal, the repository with more stars appears first.
    all_candidates.sort(
        key=lambda candidate: (
            candidate.score,
            candidate.stars or 0,
        ),
        reverse=True,
    )

    # Keep only candidates meeting the user's configured threshold.
    accepted = [
        candidate
        for candidate in all_candidates
        if candidate.score >= args.minimum_score
    ]

    print(
        f"\n[*] Found {len(all_candidates)} total candidates; "
        f"{len(accepted)} passed the minimum score of "
        f"{args.minimum_score}."
    )

    # Handle the case where nothing meets the threshold.
    if not accepted:
        print(
            "\nNo sufficiently trustworthy PoC candidates "
            "were identified.\n"
            "This does not prove that no PoC exists. "
            "Try reviewing the vendor advisory or raising "
            "--maximum-results, but do not lower the trust "
            "threshold without manually inspecting each result."
        )

    else:
        # Print accepted candidates starting from result number 1.
        for position, candidate in enumerate(
            accepted,
            start=1,
        ):
            print_candidate(
                candidate,
                position,
            )

    # -----------------------------------------------------------------------
    # Optional JSON output
    # -----------------------------------------------------------------------

    if args.json_file:
        # Build a dictionary containing both accepted and rejected results.
        output = {
            "query": args.cve,

            # Record when the output was generated.
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "nvd": {
                "status": status,
                "description": description,
            },

            "minimum_score": args.minimum_score,

            # asdict converts each Candidate dataclass into a dictionary.
            "accepted_results": [
                asdict(item)
                for item in accepted
            ],

            "all_results": [
                asdict(item)
                for item in all_candidates
            ],

            "warning": (
                "Results are heuristic. Never execute "
                "untrusted PoC code outside an isolated "
                "and authorised test environment."
            ),
        }

        # Convert the provided output path into a Path object.
        destination = Path(
            args.json_file
        )

        try:
            # Write formatted JSON using UTF-8.
            destination.write_text(
                json.dumps(
                    output,

                    # Make the JSON readable for humans.
                    indent=2,

                    # Preserve normal Unicode characters rather than
                    # converting every non-ASCII character into escapes.
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        except OSError as exc:
            # Handle file-system errors such as:
            #
            # - permission denied
            # - invalid destination
            # - missing directory
            # - disk full
            print(
                f"[ERROR] Could not write JSON output: {exc}",
                file=sys.stderr,
            )

            return 1

        print(
            f"\n[+] JSON results saved to {destination}"
        )

    # Final reminder explaining the program's limitations.
    print(
        "\n[SAFETY] The script only identifies references. "
        "It does not verify that code is harmless, and it "
        "intentionally does not clone or run it."
    )

    # Successful exit.
    return 0


# ---------------------------------------------------------------------------
# Python entry point
# ---------------------------------------------------------------------------

# When this file is executed directly:
#
#     python3 script.py -o CVE-2024-12345
#
# Python sets __name__ to "__main__", causing main() to run.
#
# When this file is imported as a module:
#
#     import script
#
# main() does not run automatically.
if __name__ == "__main__":
    # SystemExit uses the integer returned by main() as the process exit code.
    raise SystemExit(main())

