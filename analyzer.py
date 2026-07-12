import ast
import json
from pathlib import Path

import pandas as pd


DATA_FOLDER = Path(__file__).parent / "official_data"
MAINTENANCE_CUTOFF = pd.Timestamp("2024-04-01")


def normalize_text(value):
    """Standardize text for reliable comparison."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower()


def version_list(value):
    """Convert affected_versions into a clean list of strings."""
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    try:
        if pd.isna(value):
            return []
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, (list, tuple, set)):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except (ValueError, SyntaxError):
        pass
    separator = ";" if ";" in text else "," if "," in text else None
    if separator:
        return [item.strip() for item in text.split(separator) if item.strip()]
    return [text]


def to_boolean(value):
    """Convert JSON/CSV boolean-like values into a real Boolean."""
    if isinstance(value, bool):
        return value
    return normalize_text(value) in {"true", "yes", "1", "y"}


def load_json(filename):
    """Load one official JSON file."""
    with open(DATA_FOLDER / filename, "r", encoding="utf-8") as file:
        return json.load(file)


def normalize_applications(raw_applications):
    """Prepare official application records."""
    applications = pd.DataFrame(raw_applications).copy()
    applications["app_id"] = applications["app_id"].astype(str)
    applications["app_name"] = applications["name"].astype(str)
    applications["business_criticality"] = (
        applications["criticality"].astype(str).str.lower()
    )
    applications["owner"] = applications["business_owner"]
    return applications


def build_parent_lookup(transitive_dependencies):
    """Map each application/library/version to its possible parents."""
    parent_lookup = {}
    for _, edge in transitive_dependencies.iterrows():
        key = (
            str(edge["application_id"]),
            normalize_text(edge["child_library"]),
            str(edge["child_version"]).strip(),
        )
        parent_lookup.setdefault(key, []).append(str(edge["parent_library"]))
    return parent_lookup


def normalize_dependencies(raw_dependencies, applications, transitive_dependencies):
    """Convert the official SBOM schema into ChainGuard's internal schema."""
    app_name_lookup = dict(zip(applications["app_id"], applications["app_name"]))
    parent_lookup = build_parent_lookup(transitive_dependencies)
    rows = []

    for _, dependency in raw_dependencies.iterrows():
        app_id = str(dependency["application_id"])
        component = str(dependency["library"]).strip()
        version = str(dependency["version"]).strip()
        dependency_type = normalize_text(dependency["dependency_type"])

        if dependency_type == "direct":
            parent = app_name_lookup.get(app_id, str(dependency["application_name"]))
            direct = "yes"
            depth = 1
        else:
            lookup_key = (app_id, normalize_text(component), version)
            possible_parents = parent_lookup.get(lookup_key, [])
            parent = possible_parents[0] if possible_parents else "Unknown Parent"
            direct = "no"
            depth = 2

        rows.append(
            {
                "dependency_id": dependency["dep_id"],
                "dep_id": dependency["dep_id"],
                "app_id": app_id,
                "application_id": app_id,
                "app_name": str(dependency["application_name"]),
                "parent_component": parent,
                "component": component,
                "library": component,
                "version": version,
                "license": dependency["license"],
                "direct": direct,
                "dependency_type": dependency["dependency_type"],
                "dependency_depth": depth,
                "last_updated": dependency["last_updated"],
                "transitive_deps": dependency.get("transitive_deps", ""),
                "reachability": "unknown",
                "custom_patch_id": "",
            }
        )

    return pd.DataFrame(rows)


def load_data():
    """Load and normalize all six official dataset files."""
    raw_applications = load_json("applications.json")
    raw_vulnerabilities = load_json("vulnerability_db.json")
    raw_license_rules = load_json("license_rules.json")
    raw_transitive = load_json("transitive_dependencies.json")

    raw_dependencies = pd.read_csv(DATA_FOLDER / "sbom_dependencies.csv")
    labels = pd.read_csv(
        DATA_FOLDER / "dependency_labels.csv",
        encoding="cp1252",
    )

    applications = normalize_applications(raw_applications)
    vulnerabilities = pd.DataFrame(raw_vulnerabilities)
    license_rules = pd.DataFrame(raw_license_rules)
    transitive = pd.DataFrame(raw_transitive)
    dependencies = normalize_dependencies(
        raw_dependencies,
        applications,
        transitive,
    )

    return {
        "applications": applications,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
        "license_rules": license_rules,
        "transitive": transitive,
        "transitive_dependencies": transitive,
        "labels": labels,
    }


def check_vulnerability(dependency, vulnerabilities):
    """Return confirmed, potential, or no vulnerability evidence."""
    component = normalize_text(dependency["component"])
    installed_version = str(dependency["version"]).strip()
    library_matches = vulnerabilities[
        vulnerabilities["library"].apply(normalize_text) == component
    ]

    if library_matches.empty:
        return {
            "status": "none",
            "matches": [],
            "reason": "No CVE exists for this library in the supplied database.",
        }

    confirmed_matches = []
    for _, vulnerability in library_matches.iterrows():
        affected_versions = version_list(vulnerability["affected_versions"])
        if installed_version in affected_versions:
            confirmed_matches.append(vulnerability.to_dict())

    if confirmed_matches:
        return {
            "status": "confirmed",
            "matches": confirmed_matches,
            "reason": (
                "The library and installed version both match the "
                "vulnerability database."
            ),
        }

    return {
        "status": "potential",
        "matches": library_matches.to_dict(orient="records"),
        "reason": (
            "The library has known CVEs, but the installed version is not "
            "listed in affected_versions."
        ),
    }


def check_license(dependency, application, license_rules):
    """Check whether a dependency licence is compatible with the application."""
    dependency_license = normalize_text(dependency["license"])

    if dependency_license in {"", "unknown", "none", "nan"}:
        return {
            "status": "unknown",
            "risk_level": "high",
            "condition": "Licence information is missing.",
        }

    matching_rule = license_rules[
        (license_rules["spdx"].apply(normalize_text) == dependency_license)
        | (license_rules["license"].apply(normalize_text) == dependency_license)
    ]

    if matching_rule.empty:
        return {
            "status": "unknown",
            "risk_level": "high",
            "condition": "No matching licence rule exists.",
        }

    rule = matching_rule.iloc[0]
    application_model = normalize_text(application.get("license_model", "proprietary"))
    compatible = to_boolean(rule["compatible_with_proprietary"])
    risk_level = normalize_text(rule["risk_level"])

    if application_model == "proprietary" and not compatible:
        status = "conflict"
    elif risk_level == "medium":
        status = "conditional"
    else:
        status = "compatible"

    return {
        "status": status,
        "risk_level": risk_level,
        "condition": str(rule["notes"]),
    }


def check_maintenance(dependency):
    """Identify dependencies not updated within the accepted period."""
    last_updated = pd.to_datetime(dependency["last_updated"], errors="coerce")

    if pd.isna(last_updated):
        return {
            "status": "unknown",
            "risk": True,
            "reason": "Last update date is unavailable.",
        }

    if last_updated < MAINTENANCE_CUTOFF:
        return {
            "status": "unmaintained",
            "risk": True,
            "reason": "Library was last updated before April 2024.",
        }

    return {
        "status": "active",
        "risk": False,
        "reason": "Library was updated within the accepted period.",
    }


def calculate_risk_score(
    application,
    vulnerability_result,
    license_result,
    maintenance_result,
):
    """Calculate the contextual dependency risk score."""
    vulnerability_points = 0
    license_points = 0
    maintenance_points = 0
    explanations = []

    vulnerability_status = vulnerability_result["status"]
    matches = vulnerability_result["matches"]

    if vulnerability_status == "confirmed" and matches:
        maximum_cvss = max(float(match["cvss_score"]) for match in matches)
        vulnerability_points = maximum_cvss * 4
        high_exploitability = any(
            normalize_text(match["exploitability"]) == "high" for match in matches
        )
        no_patch = any(not to_boolean(match["patch_available"]) for match in matches)

        if high_exploitability:
            vulnerability_points += 10
            explanations.append("High exploitability")
        if no_patch:
            vulnerability_points += 5
            explanations.append("No patch available")

        vulnerability_points = min(vulnerability_points, 50)
        explanations.append(f"Confirmed CVE match; maximum CVSS {maximum_cvss}")

    elif vulnerability_status == "potential" and matches:
        maximum_cvss = max(float(match["cvss_score"]) for match in matches)
        vulnerability_points = min(maximum_cvss * 1.5, 15)
        explanations.append(
            "Potential CVE: library matches but installed version is not listed"
        )

    licence_status = license_result["status"]
    if licence_status == "conflict":
        license_points = 20
        explanations.append("Licence conflict")
    elif licence_status == "unknown":
        license_points = 15
        explanations.append("Unknown licence")
    elif licence_status == "conditional":
        license_points = 8
        explanations.append("Conditional licence review")

    if maintenance_result["status"] == "unmaintained":
        maintenance_points = 15
        explanations.append("Unmaintained library")
    elif maintenance_result["status"] == "unknown":
        maintenance_points = 10
        explanations.append("Unknown maintenance status")

    criticality = normalize_text(application.get("criticality", "medium"))
    criticality_points = {"low": 0, "medium": 5, "high": 10, "critical": 15}
    context_points = criticality_points.get(criticality, 5)
    explanations.append(f"{criticality.title()} business criticality")

    total = round(
        min(
            vulnerability_points
            + license_points
            + maintenance_points
            + context_points,
            100,
        )
    )

    if total >= 75:
        severity = "critical"
    elif total >= 50:
        severity = "high"
    elif total >= 25:
        severity = "medium"
    else:
        severity = "low"

    return {
        "risk_score": total,
        "severity": severity,
        "vulnerability_points": round(vulnerability_points),
        "license_points": license_points,
        "maintenance_points": maintenance_points,
        "context_points": context_points,
        "explanation": "; ".join(dict.fromkeys(explanations)),
    }


def analyze_dependencies(data):
    """Analyse every dependency and return one finding per SBOM row."""
    applications = data["applications"]
    dependencies = data["dependencies"]
    vulnerabilities = data["vulnerabilities"]
    license_rules = data["license_rules"]
    application_lookup = applications.set_index("app_id")
    findings = []

    for _, dependency in dependencies.iterrows():
        app_id = str(dependency["app_id"])
        if app_id not in application_lookup.index:
            continue

        application = application_lookup.loc[app_id]
        vulnerability_result = check_vulnerability(dependency, vulnerabilities)
        license_result = check_license(dependency, application, license_rules)
        maintenance_result = check_maintenance(dependency)
        score_result = calculate_risk_score(
            application,
            vulnerability_result,
            license_result,
            maintenance_result,
        )

        matches = vulnerability_result["matches"]
        cve_ids = sorted(
            {str(match["cve_id"]).strip() for match in matches if match.get("cve_id")}
        )

        patched_versions = set()
        for match in matches:
            fixed_version = match.get("fixed_version")
            cleaned_fixed_version = normalize_text(fixed_version)
            if cleaned_fixed_version not in {"", "none", "nan"}:
                patched_versions.add(str(fixed_version).strip())

        status = vulnerability_result["status"]
        vulnerable_value = {
            "confirmed": "yes",
            "potential": "potential",
            "none": "no",
        }.get(status, "no")

        findings.append(
            {
                "dependency_id": dependency["dependency_id"],
                "app_id": app_id,
                "app_name": application["app_name"],
                "component": dependency["component"],
                "version": dependency["version"],
                "direct": dependency["direct"],
                "dependency_depth": dependency["dependency_depth"],
                "parent_component": dependency["parent_component"],
                "vulnerable": vulnerable_value,
                "vulnerability_status": status,
                "version_evidence": vulnerability_result["reason"],
                "cve_count": len(cve_ids),
                "cve_ids": ", ".join(cve_ids),
                "patched_versions": ", ".join(sorted(patched_versions)),
                "license": dependency["license"],
                "license_status": license_result["status"],
                "maintenance_status": maintenance_result["status"],
                "reachability": dependency.get("reachability", "unknown"),
                **score_result,
            }
        )

    return pd.DataFrame(findings)


if __name__ == "__main__":
    datasets = load_data()
    results = analyze_dependencies(datasets)

    print("Official analysis completed.")
    print("Dependencies:", len(results))
    print(
        "Confirmed vulnerabilities:",
        int((results["vulnerability_status"] == "confirmed").sum()),
    )
    print(
        "Potential vulnerabilities:",
        int((results["vulnerability_status"] == "potential").sum()),
    )
    print(
        "No library CVE:",
        int((results["vulnerability_status"] == "none").sum()),
    )