import ast
import re

import pandas as pd
import streamlit as st

from analyzer import load_data


st.set_page_config(
    page_title="Official Data Quality",
    page_icon="🔍",
    layout="wide"
)

st.title("Official Dataset Quality Assessment")

st.write(
    "Validate consistency between the SBOM, "
    "vulnerability database and ground-truth labels."
)


def extract_cve(explanation):
    """Extract a CVE identifier from an explanation."""

    match = re.search(
        r"CVE-\d{4}-\d+",
        str(explanation)
    )

    if match:
        return match.group(0)

    return ""


def convert_affected_versions(value):
    """Convert affected_versions into a list of strings."""

    if isinstance(
        value,
        (
            list,
            tuple,
            set
        )
    ):
        return [
            str(version).strip()
            for version in value
            if str(version).strip()
        ]

    if value is None:
        return []

    try:
        if pd.isna(value):
            return []
    except (TypeError, ValueError):
        pass

    text_value = str(value).strip()

    if not text_value:
        return []

    try:
        parsed_value = ast.literal_eval(
            text_value
        )

        if isinstance(
            parsed_value,
            (
                list,
                tuple,
                set
            )
        ):
            return [
                str(version).strip()
                for version in parsed_value
                if str(version).strip()
            ]

    except (
        ValueError,
        SyntaxError
    ):
        pass

    if ";" in text_value:

        return [
            version.strip()
            for version in text_value.split(";")
            if version.strip()
        ]

    if "," in text_value:

        return [
            version.strip()
            for version in text_value.split(",")
            if version.strip()
        ]

    return [
        text_value
    ]


try:
    data = load_data()

    dependencies = data[
        "dependencies"
    ].copy()

    vulnerabilities = data[
        "vulnerabilities"
    ].copy()

    labels = data[
        "labels"
    ].copy()

    transitive = data.get(
        "transitive_dependencies",
        data.get(
            "transitive",
            pd.DataFrame()
        )
    )

    required_dependency_columns = [
        "dependency_id",
        "component",
        "version",
        "license",
        "app_id"
    ]

    missing_dependency_columns = [
        column
        for column in required_dependency_columns
        if column not in dependencies.columns
    ]

    if missing_dependency_columns:

        raise ValueError(
            "Missing dependency columns: "
            + ", ".join(
                missing_dependency_columns
            )
        )

    required_label_columns = [
        "dep_id",
        "risk_type",
        "explanation"
    ]

    missing_label_columns = [
        column
        for column in required_label_columns
        if column not in labels.columns
    ]

    if missing_label_columns:

        raise ValueError(
            "Missing label columns: "
            + ", ".join(
                missing_label_columns
            )
        )

    dependency_evidence = dependencies[
        required_dependency_columns
    ].rename(
        columns={
            "version":
                "installed_version"
        }
    )

    combined = labels.merge(
        dependency_evidence,
        left_on="dep_id",
        right_on="dependency_id",
        how="left"
    )

    vulnerability_labels = combined[
        combined[
            "risk_type"
        ]
        .astype(str)
        .str.contains(
            "VULNER",
            case=False,
            na=False
        )
    ].copy()

    vulnerability_labels[
        "label_cve"
    ] = vulnerability_labels[
        "explanation"
    ].apply(
        extract_cve
    )

    vulnerability_lookup = {
        str(row["cve_id"]).strip():
            row

        for _, row
        in vulnerabilities.iterrows()
    }

    checks = []

    for _, row in vulnerability_labels.iterrows():

        cve_id = str(
            row["label_cve"]
        ).strip()

        cve_record = vulnerability_lookup.get(
            cve_id
        )

        installed_version = str(
            row.get(
                "installed_version",
                ""
            )
        ).strip()

        dependency_library = str(
            row.get(
                "component",
                ""
            )
        ).strip()

        if cve_record is None:

            checks.append(
                {
                    "dep_id":
                        row["dep_id"],

                    "library":
                        dependency_library,

                    "installed_version":
                        installed_version,

                    "label_cve":
                        cve_id,

                    "cve_exists":
                        False,

                    "cve_library":
                        "",

                    "library_matches":
                        False,

                    "affected_versions":
                        "",

                    "version_listed":
                        False,

                    "result":
                        "CVE missing from database"
                }
            )

            continue

        affected_versions = (
            convert_affected_versions(
                cve_record[
                    "affected_versions"
                ]
            )
        )

        cve_library = str(
            cve_record[
                "library"
            ]
        ).strip()

        library_matches = (
            cve_library.lower()
            ==
            dependency_library.lower()
        )

        version_listed = (
            installed_version
            in affected_versions
        )

        if (
            library_matches
            and version_listed
        ):

            result = "Consistent"

        elif library_matches:

            result = (
                "Library matches, version not listed"
            )

        else:

            result = "Library mismatch"

        checks.append(
            {
                "dep_id":
                    row["dep_id"],

                "library":
                    dependency_library,

                "installed_version":
                    installed_version,

                "label_cve":
                    cve_id,

                "cve_exists":
                    True,

                "cve_library":
                    cve_library,

                "library_matches":
                    library_matches,

                "affected_versions":
                    ", ".join(
                        affected_versions
                    ),

                "version_listed":
                    version_listed,

                "result":
                    result
            }
        )

    quality_columns = [
        "dep_id",
        "library",
        "installed_version",
        "label_cve",
        "cve_exists",
        "cve_library",
        "library_matches",
        "affected_versions",
        "version_listed",
        "result"
    ]

    quality_results = pd.DataFrame(
        checks,
        columns=quality_columns
    )

    total_vulnerability_labels = len(
        quality_results
    )

    if quality_results.empty:

        library_match_count = 0
        exact_version_matches = 0
        version_mismatches = 0

    else:

        library_match_count = int(
            quality_results[
                "library_matches"
            ]
            .fillna(False)
            .astype(bool)
            .sum()
        )

        exact_version_matches = int(
            quality_results[
                "version_listed"
            ]
            .fillna(False)
            .astype(bool)
            .sum()
        )

        version_mismatches = int(
            (
                quality_results[
                    "version_listed"
                ]
                .fillna(False)
                == False
            ).sum()
        )

    matched_dependency_rows = int(
        combined[
            "dependency_id"
        ].notna().sum()
    )

    unmatched_label_rows = int(
        combined[
            "dependency_id"
        ].isna().sum()
    )

    duplicate_dependency_ids = int(
        dependencies[
            "dependency_id"
        ].duplicated().sum()
    )

    st.header(
        "Dataset Integrity Overview"
    )

    q1, q2, q3, q4 = st.columns(4)

    q1.metric(
        "Dependency Rows",
        len(dependencies)
    )

    q2.metric(
        "Ground-Truth Rows",
        len(labels)
    )

    q3.metric(
        "Transitive Edges",
        len(transitive)
    )

    q4.metric(
        "Matched Label IDs",
        matched_dependency_rows
    )

    if unmatched_label_rows > 0:

        st.warning(
            f"{unmatched_label_rows} ground-truth rows "
            "could not be matched with an SBOM dependency."
        )

    else:

        st.success(
            "Every ground-truth label matches an SBOM "
            "dependency ID."
        )

    st.divider()

    st.header(
        "Vulnerability Evidence Check"
    )

    v1, v2, v3, v4 = st.columns(4)

    v1.metric(
        "Vulnerability Labels",
        total_vulnerability_labels
    )

    v2.metric(
        "Correct CVE Library",
        library_match_count
    )

    v3.metric(
        "Exact Version Matches",
        exact_version_matches
    )

    v4.metric(
        "Version Mismatches",
        version_mismatches
    )

    if version_mismatches > 0:

        st.error(
            f"{version_mismatches} vulnerability-labelled "
            "dependencies reference CVEs, but their "
            "installed versions are absent from the "
            "affected_versions field."
        )

        st.info(
            "ChainGuard handles these records as Potential "
            "Vulnerabilities instead of presenting them as "
            "confirmed affected-version matches."
        )

    elif total_vulnerability_labels > 0:

        st.success(
            "Every vulnerability-labelled dependency has "
            "an exact affected-version match."
        )

    else:

        st.info(
            "No vulnerability-labelled records were found."
        )

    if duplicate_dependency_ids > 0:

        st.warning(
            f"{duplicate_dependency_ids} duplicate "
            "dependency IDs were detected."
        )

    else:

        st.success(
            "All dependency IDs are unique."
        )

    st.divider()

    st.header(
        "Version Consistency Evidence"
    )

    selected_result = st.selectbox(
        "Filter evidence",
        [
            "All",
            "Consistent",
            "Library matches, version not listed",
            "Library mismatch",
            "CVE missing from database"
        ],
        key="data_quality_filter"
    )

    if selected_result == "All":

        displayed_results = (
            quality_results
        )

    else:

        displayed_results = (
            quality_results[
                quality_results[
                    "result"
                ]
                == selected_result
            ]
        )

    st.write(
        f"Displaying {len(displayed_results)} "
        "evidence records."
    )

    st.dataframe(
        displayed_results,
        width="stretch",
        hide_index=True
    )

    st.download_button(
        "Download Data-Quality Findings",
        data=quality_results.to_csv(
            index=False
        ),
        file_name=(
            "official_dataset_quality_findings.csv"
        ),
        mime="text/csv"
    )

    st.warning(
        "Ground-truth labels are used only for performance "
        "evaluation and data-quality checking. ChainGuard "
        "does not use them to generate risk predictions."
    )


except Exception as error:

    st.error(
        f"Unable to complete the data-quality check: "
        f"{error}"
    )
