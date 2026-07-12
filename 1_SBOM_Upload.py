import json
from pathlib import Path

import pandas as pd
import streamlit as st

from analyzer import load_data, analyze_dependencies


st.set_page_config(
    page_title="SBOM Upload",
    page_icon="📤",
    layout="wide"
)

st.title("Upload and Analyse an SBOM")

st.write(
    "Upload an SBOM in CSV or CycloneDX JSON format. "
    "ChainGuard will check its dependencies for vulnerabilities, "
    "licence conflicts and maintenance risks."
)


def clean_text(value, default="unknown"):
    """Return a clean text value."""

    if pd.isna(value):
        return default

    value = str(value).strip()

    if not value:
        return default

    return value


def is_direct_dependency(value):
    """Convert different direct-dependency formats into yes or no."""

    value = clean_text(value, "no").lower()

    return value in [
        "yes",
        "true",
        "1",
        "direct",
        "primary"
    ]


def normalise_csv_sbom(uploaded_dataframe):
    """
    Convert an uploaded CSV into the format used by ChainGuard.

    Supported formats:
    1. Official hackathon SBOM format
    2. ChainGuard internal format
    3. Simple component/version/licence format
    """

    dataframe = uploaded_dataframe.copy()

    dataframe.columns = [
        str(column).strip().lower()
        for column in dataframe.columns
    ]

    if "library" in dataframe.columns:
        component_column = "library"

    elif "component" in dataframe.columns:
        component_column = "component"

    elif "name" in dataframe.columns:
        component_column = "name"

    else:
        raise ValueError(
            "The uploaded CSV must contain a 'library', "
            "'component' or 'name' column."
        )

    if "version" not in dataframe.columns:
        raise ValueError(
            "The uploaded CSV must contain a 'version' column."
        )

    normalised_rows = []

    for row_number, row in dataframe.iterrows():

        app_id = clean_text(
            row.get(
                "application_id",
                row.get(
                    "app_id",
                    "UPLOAD001"
                )
            ),
            "UPLOAD001"
        )

        app_name = clean_text(
            row.get(
                "application_name",
                row.get(
                    "app_name",
                    "Uploaded Application"
                )
            ),
            "Uploaded Application"
        )

        component = clean_text(
            row.get(component_column),
            "unknown-component"
        )

        dependency_type = row.get(
            "dependency_type",
            row.get(
                "direct",
                "direct"
            )
        )

        direct = is_direct_dependency(
            dependency_type
        )

        if direct:
            parent_component = clean_text(
                row.get(
                    "parent_component",
                    app_name
                ),
                app_name
            )

            dependency_depth = 1

        else:
            parent_component = clean_text(
                row.get(
                    "parent_component",
                    "Transitive Dependency"
                ),
                "Transitive Dependency"
            )

            dependency_depth = 2

        dependency_id = clean_text(
            row.get(
                "dep_id",
                row.get(
                    "dependency_id",
                    f"UPLOAD-DEP-{row_number + 1:04d}"
                )
            ),
            f"UPLOAD-DEP-{row_number + 1:04d}"
        )

        normalised_rows.append(
            {
                "dependency_id": dependency_id,
                "app_id": app_id,
                "app_name": app_name,
                "parent_component": parent_component,
                "component": component,
                "version": clean_text(
                    row.get("version"),
                    "unknown"
                ),
                "license": clean_text(
                    row.get(
                        "license",
                        row.get(
                            "licence",
                            "Unknown"
                        )
                    ),
                    "Unknown"
                ),
                "last_updated": clean_text(
                    row.get(
                        "last_updated",
                        ""
                    ),
                    ""
                ),
                "direct": (
                    "yes"
                    if direct
                    else "no"
                ),
                "dependency_depth": dependency_depth,
                "transitive_deps": clean_text(
                    row.get(
                        "transitive_deps",
                        ""
                    ),
                    ""
                ),
                "reachability": clean_text(
                    row.get(
                        "reachability",
                        "unknown"
                    ),
                    "unknown"
                ),
                "custom_patch_id": clean_text(
                    row.get(
                        "custom_patch_id",
                        ""
                    ),
                    ""
                )
            }
        )

    return pd.DataFrame(normalised_rows)


def normalise_cyclonedx_sbom(sbom_document):
    """Convert a CycloneDX JSON SBOM into ChainGuard format."""

    metadata = sbom_document.get(
        "metadata",
        {}
    )

    application_details = metadata.get(
        "component",
        {}
    )

    app_name = clean_text(
        application_details.get(
            "name",
            "Uploaded Application"
        ),
        "Uploaded Application"
    )

    app_id = clean_text(
        application_details.get(
            "bom-ref",
            "UPLOAD001"
        ),
        "UPLOAD001"
    )

    components = sbom_document.get(
        "components",
        []
    )

    if not components:
        raise ValueError(
            "The CycloneDX file does not contain any components."
        )

    component_lookup = {}

    for component in components:

        component_reference = clean_text(
            component.get(
                "bom-ref",
                component.get(
                    "name",
                    ""
                )
            ),
            ""
        )

        if component_reference:
            component_lookup[
                component_reference
            ] = component

    dependency_entries = sbom_document.get(
        "dependencies",
        []
    )

    parent_lookup = {}

    root_direct_components = set()

    root_reference = clean_text(
        application_details.get(
            "bom-ref",
            ""
        ),
        ""
    )

    for dependency_entry in dependency_entries:

        parent_reference = clean_text(
            dependency_entry.get(
                "ref",
                ""
            ),
            ""
        )

        child_references = dependency_entry.get(
            "dependsOn",
            []
        )

        if parent_reference == root_reference:
            root_direct_components.update(
                child_references
            )

        for child_reference in child_references:

            if child_reference not in parent_lookup:
                parent_lookup[
                    child_reference
                ] = parent_reference

    normalised_rows = []

    for row_number, component in enumerate(
        components,
        start=1
    ):

        component_reference = clean_text(
            component.get(
                "bom-ref",
                component.get(
                    "name",
                    f"component-{row_number}"
                )
            ),
            f"component-{row_number}"
        )

        component_name = clean_text(
            component.get(
                "name",
                component_reference
            ),
            component_reference
        )

        licenses = component.get(
            "licenses",
            []
        )

        detected_license = "Unknown"

        if licenses:

            first_license = licenses[0]

            if "license" in first_license:
                detected_license = clean_text(
                    first_license[
                        "license"
                    ].get(
                        "id",
                        first_license[
                            "license"
                        ].get(
                            "name",
                            "Unknown"
                        )
                    ),
                    "Unknown"
                )

            elif "expression" in first_license:
                detected_license = clean_text(
                    first_license.get(
                        "expression"
                    ),
                    "Unknown"
                )

        direct = (
            component_reference
            in root_direct_components
        )

        parent_reference = parent_lookup.get(
            component_reference,
            ""
        )

        if direct:
            parent_name = app_name
            dependency_depth = 1

        else:
            parent_component = component_lookup.get(
                parent_reference,
                {}
            )

            parent_name = clean_text(
                parent_component.get(
                    "name",
                    "Transitive Dependency"
                ),
                "Transitive Dependency"
            )

            dependency_depth = 2

        normalised_rows.append(
            {
                "dependency_id":
                    f"UPLOAD-DEP-{row_number:04d}",

                "app_id":
                    app_id,

                "app_name":
                    app_name,

                "parent_component":
                    parent_name,

                "component":
                    component_name,

                "version":
                    clean_text(
                        component.get(
                            "version",
                            "unknown"
                        ),
                        "unknown"
                    ),

                "license":
                    detected_license,

                "last_updated":
                    "",

                "direct":
                    "yes" if direct else "no",

                "dependency_depth":
                    dependency_depth,

                "transitive_deps":
                    "",

                "reachability":
                    "unknown",

                "custom_patch_id":
                    ""
            }
        )

    return pd.DataFrame(normalised_rows)


def create_uploaded_applications(dependencies):
    """Create application records from the uploaded dependencies."""

    application_rows = []

    application_pairs = dependencies[
        [
            "app_id",
            "app_name"
        ]
    ].drop_duplicates()

    for _, application in application_pairs.iterrows():

        application_rows.append(
            {
                "app_id":
                    application["app_id"],

                "app_name":
                    application["app_name"],

                "name":
                    application["app_name"],

                "criticality":
                    "medium",

                "business_criticality":
                    "medium",

                "license_model":
                    "proprietary",

                "language":
                    "Unknown",

                "business_owner":
                    "Uploaded SBOM Owner",

                "owner":
                    "Uploaded SBOM Owner",

                "department":
                    "Uploaded Data",

                "deployment":
                    "Unknown",

                "environment":
                    "Unknown",

                "internet_facing":
                    "Unknown",

                "data_sensitivity":
                    "Unknown"
            }
        )

    return pd.DataFrame(application_rows)


uploaded_file = st.file_uploader(
    "Choose an SBOM file",
    type=[
        "csv",
        "json"
    ],
    help=(
        "Upload the official SBOM CSV, a simple dependency "
        "CSV or a CycloneDX JSON file."
    )
)


if uploaded_file is None:

    st.info(
        "Upload a CSV or CycloneDX JSON file to begin."
    )

    st.subheader("Minimum CSV columns")

    example_dataframe = pd.DataFrame(
        [
            {
                "component": "log4j-core",
                "version": "2.14.1",
                "license": "Apache-2.0",
                "last_updated": "2021-12-01",
                "direct": "yes"
            },
            {
                "component": "commons-text",
                "version": "1.9",
                "license": "Apache-2.0",
                "last_updated": "2022-02-15",
                "direct": "no"
            }
        ]
    )

    st.dataframe(
        example_dataframe,
        width="stretch",
        hide_index=True
    )

else:

    try:
        file_suffix = Path(
            uploaded_file.name
        ).suffix.lower()

        if file_suffix == ".csv":

            uploaded_dataframe = pd.read_csv(
                uploaded_file
            )

            uploaded_dependencies = (
                normalise_csv_sbom(
                    uploaded_dataframe
                )
            )

        elif file_suffix == ".json":

            sbom_document = json.load(
                uploaded_file
            )

            uploaded_dependencies = (
                normalise_cyclonedx_sbom(
                    sbom_document
                )
            )

        else:
            raise ValueError(
                "Only CSV and JSON files are supported."
            )

        if uploaded_dependencies.empty:
            raise ValueError(
                "No dependencies were found in the uploaded file."
            )

        uploaded_applications = (
            create_uploaded_applications(
                uploaded_dependencies
            )
        )

        official_data = load_data()

        uploaded_data = dict(
            official_data
        )

        uploaded_data[
            "applications"
        ] = uploaded_applications

        uploaded_data[
            "dependencies"
        ] = uploaded_dependencies

        uploaded_data[
            "labels"
        ] = pd.DataFrame()

        uploaded_data[
            "ground_truth"
        ] = pd.DataFrame()

        results = analyze_dependencies(
            uploaded_data
        )

        st.success(
            f"SBOM analysed successfully. "
            f"{len(uploaded_dependencies)} dependencies were checked."
        )

        st.caption(
            "The uploaded SBOM was checked against the "
            "hackathon's supplied vulnerability and licence databases."
        )

        confirmed_count = int(
            (
                results[
                    "vulnerability_status"
                ]
                == "confirmed"
            ).sum()
        )

        potential_count = int(
            (
                results[
                    "vulnerability_status"
                ]
                == "potential"
            ).sum()
        )

        licence_conflicts = int(
            (
                results[
                    "license_status"
                ]
                == "conflict"
            ).sum()
        )

        unmaintained_count = int(
            (
                results[
                    "maintenance_status"
                ]
                == "unmaintained"
            ).sum()
        )

        critical_count = int(
            (
                results[
                    "severity"
                ]
                == "critical"
            ).sum()
        )

        metric1, metric2, metric3, metric4, metric5 = (
            st.columns(5)
        )

        metric1.metric(
            "Confirmed Vulnerabilities",
            confirmed_count
        )

        metric2.metric(
            "Potential Vulnerabilities",
            potential_count
        )

        metric3.metric(
            "Licence Conflicts",
            licence_conflicts
        )

        metric4.metric(
            "Unmaintained",
            unmaintained_count
        )

        metric5.metric(
            "Critical Findings",
            critical_count
        )

        if potential_count > 0:

            st.warning(
                f"{potential_count} dependencies use libraries "
                "with known CVEs, but their installed versions "
                "are not explicitly listed as affected. These "
                "findings require analyst verification."
            )

        st.divider()

        st.header("Uploaded Dependencies")

        st.dataframe(
            uploaded_dependencies,
            width="stretch",
            hide_index=True
        )

        st.divider()

        st.header("Risk Analysis Results")

        display_columns = [
            "app_name",
            "component",
            "version",
            "direct",
            "vulnerability_status",
            "version_evidence",
            "cve_ids",
            "license_status",
            "maintenance_status",
            "risk_score",
            "severity",
            "explanation"
        ]

        available_columns = [
            column
            for column in display_columns
            if column in results.columns
        ]

        sorted_results = results.sort_values(
            by="risk_score",
            ascending=False
        )

        st.dataframe(
            sorted_results[
                available_columns
            ],
            width="stretch",
            hide_index=True
        )

        st.download_button(
            "Download Analysis Results",
            data=sorted_results.to_csv(
                index=False
            ),
            file_name="uploaded_sbom_analysis.csv",
            mime="text/csv"
        )

    except Exception as error:

        st.error(
            f"Unable to analyse the uploaded SBOM: {error}"
        )