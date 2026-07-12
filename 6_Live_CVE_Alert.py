import re
from datetime import date

import pandas as pd
import streamlit as st

from analyzer import (
    load_data,
    analyze_dependencies
)


st.set_page_config(
    page_title="Live CVE Alert",
    page_icon="🚨",
    layout="wide"
)

st.title("Live CVE Alert Simulator")

st.write(
    "Simulate a newly disclosed vulnerability and "
    "immediately identify every affected application."
)


def get_severity(cvss_score):
    """Convert a CVSS score into a severity."""

    if cvss_score >= 9:
        return "CRITICAL"

    if cvss_score >= 7:
        return "HIGH"

    if cvss_score >= 4:
        return "MEDIUM"

    return "LOW"


def valid_cve_id(cve_id):
    """Check whether a CVE identifier has a valid format."""

    return bool(
        re.fullmatch(
            r"CVE-\d{4}-\d{4,}",
            str(cve_id).strip().upper()
        )
    )


def convert_versions_to_list(value):
    """Convert affected versions into a list."""

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


def find_exact_simulated_exposures(
    dependencies,
    simulated_vulnerabilities
):
    """
    Match simulated CVEs using both library name
    and exact installed version.
    """

    exposure_rows = []

    if simulated_vulnerabilities.empty:
        return pd.DataFrame(
            columns=[
                "dependency_id",
                "simulated_cve_ids",
                "simulated_cve_count",
                "maximum_simulated_cvss"
            ]
        )

    for _, vulnerability in (
        simulated_vulnerabilities.iterrows()
    ):

        affected_library = str(
            vulnerability[
                "library"
            ]
        ).strip().lower()

        affected_versions = (
            convert_versions_to_list(
                vulnerability[
                    "affected_versions"
                ]
            )
        )

        matching_dependencies = dependencies[
            (
                dependencies[
                    "component"
                ]
                .astype(str)
                .str.strip()
                .str.lower()
                == affected_library
            )
            &
            (
                dependencies[
                    "version"
                ]
                .astype(str)
                .str.strip()
                .isin(
                    affected_versions
                )
            )
        ]

        for _, dependency in (
            matching_dependencies.iterrows()
        ):

            exposure_rows.append(
                {
                    "dependency_id":
                        dependency[
                            "dependency_id"
                        ],

                    "simulated_cve_id":
                        vulnerability[
                            "cve_id"
                        ],

                    "simulated_cvss":
                        float(
                            vulnerability[
                                "cvss_score"
                            ]
                        )
                }
            )

    if not exposure_rows:

        return pd.DataFrame(
            columns=[
                "dependency_id",
                "simulated_cve_ids",
                "simulated_cve_count",
                "maximum_simulated_cvss"
            ]
        )

    exposure_dataframe = pd.DataFrame(
        exposure_rows
    )

    exposure_summary = (
        exposure_dataframe.groupby(
            "dependency_id"
        )
        .agg(
            simulated_cve_ids=(
                "simulated_cve_id",
                lambda values:
                    ", ".join(
                        sorted(
                            set(
                                str(value)
                                for value in values
                            )
                        )
                    )
            ),

            simulated_cve_count=(
                "simulated_cve_id",
                "nunique"
            ),

            maximum_simulated_cvss=(
                "simulated_cvss",
                "max"
            )
        )
        .reset_index()
    )

    return exposure_summary


try:
    data = load_data()

    dependencies = data[
        "dependencies"
    ].copy()

    official_vulnerabilities = data[
        "vulnerabilities"
    ].copy()

    baseline_results = analyze_dependencies(
        data
    )

    vulnerability_columns = (
        official_vulnerabilities
        .columns
        .tolist()
    )

    if (
        "simulated_vulnerabilities"
        not in st.session_state
    ):

        st.session_state[
            "simulated_vulnerabilities"
        ] = pd.DataFrame(
            columns=vulnerability_columns
        )

    component_options = sorted(
        dependencies[
            "component"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    if not component_options:

        st.warning(
            "No dependency components are available."
        )

        st.stop()

    selected_component = st.selectbox(
        "Affected library",
        component_options,
        key="official_live_component"
    )

    component_versions = sorted(
        dependencies[
            dependencies[
                "component"
            ]
            == selected_component
        ][
            "version"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    with st.form(
        "official_live_cve_form"
    ):

        cve_id = st.text_input(
            "CVE identifier",
            value="CVE-2026-9999"
        )

        affected_versions = st.multiselect(
            "Affected installed versions",
            component_versions,
            default=component_versions[
                :min(
                    3,
                    len(component_versions)
                )
            ]
        )

        cvss_score = st.slider(
            "CVSS score",
            min_value=0.0,
            max_value=10.0,
            value=9.8,
            step=0.1
        )

        exploitability = st.selectbox(
            "Exploitability",
            [
                "HIGH",
                "MEDIUM",
                "LOW"
            ],
            key="official_live_exploitability"
        )

        patch_available = st.selectbox(
            "Patch available?",
            [
                "Yes",
                "No"
            ],
            key="official_live_patch"
        )

        fixed_version = st.text_input(
            "Fixed version",
            value="6.0.0"
        )

        description = st.text_area(
            "Vulnerability description",
            value=(
                "New simulated vulnerability announced "
                "through a live CVE feed."
            )
        )

        publish_cve = st.form_submit_button(
            "Publish CVE and Rescan",
            type="primary"
        )

    if publish_cve:

        cleaned_cve_id = (
            cve_id.strip().upper()
        )

        official_cve_ids = {
            str(value).strip().upper()
            for value in official_vulnerabilities[
                "cve_id"
            ]
            .dropna()
            .tolist()
        }

        if not cleaned_cve_id:

            st.warning(
                "Enter a CVE identifier."
            )

        elif not valid_cve_id(
            cleaned_cve_id
        ):

            st.warning(
                "Enter a valid CVE identifier, for example "
                "CVE-2026-9999."
            )

        elif (
            cleaned_cve_id
            in official_cve_ids
        ):

            st.warning(
                "This CVE already exists in the official "
                "vulnerability database. Use a different "
                "identifier for the simulation."
            )

        elif not affected_versions:

            st.warning(
                "Select at least one affected version."
            )

        elif (
            patch_available == "Yes"
            and not fixed_version.strip()
        ):

            st.warning(
                "Enter the fixed version when a patch "
                "is available."
            )

        else:

            new_vulnerability = {
                "cve_id":
                    cleaned_cve_id,

                "library":
                    selected_component,

                "affected_versions":
                    [
                        str(version).strip()
                        for version
                        in affected_versions
                    ],

                "fixed_version": (
                    fixed_version.strip()
                    if patch_available == "Yes"
                    else None
                ),

                "cvss_score":
                    float(cvss_score),

                "severity":
                    get_severity(
                        cvss_score
                    ),

                "exploitability":
                    exploitability,

                "description":
                    (
                        description.strip()
                        if description.strip()
                        else
                        "Simulated vulnerability."
                    ),

                "patch_available": (
                    patch_available
                    == "Yes"
                ),

                "published_date":
                    date.today().isoformat()
            }

            existing_simulations = (
                st.session_state[
                    "simulated_vulnerabilities"
                ].copy()
            )

            if (
                not existing_simulations.empty
                and
                "cve_id"
                in existing_simulations.columns
            ):

                existing_simulations = (
                    existing_simulations[
                        existing_simulations[
                            "cve_id"
                        ]
                        .astype(str)
                        .str.strip()
                        .str.upper()
                        != cleaned_cve_id
                    ]
                )

            new_vulnerability_frame = (
                pd.DataFrame(
                    [
                        new_vulnerability
                    ]
                )
            )

            new_vulnerability_frame = (
                new_vulnerability_frame.reindex(
                    columns=vulnerability_columns
                )
            )

            st.session_state[
                "simulated_vulnerabilities"
            ] = pd.concat(
                [
                    existing_simulations,
                    new_vulnerability_frame
                ],
                ignore_index=True
            )

            st.success(
                f"{cleaned_cve_id} was published and "
                "all applications were rescanned."
            )

    simulated_feed = st.session_state[
        "simulated_vulnerabilities"
    ].copy()

    updated_data = data.copy()

    updated_data[
        "vulnerabilities"
    ] = pd.concat(
        [
            official_vulnerabilities,
            simulated_feed
        ],
        ignore_index=True
    )

    updated_results = analyze_dependencies(
        updated_data
    )

    updated_comparison = (
        updated_results.rename(
            columns={
                "cve_count":
                    "cve_count_updated",

                "risk_score":
                    "risk_score_updated"
            }
        )
    )

    baseline_comparison = baseline_results[
        [
            "dependency_id",
            "cve_count",
            "risk_score"
        ]
    ].rename(
        columns={
            "cve_count":
                "cve_count_baseline",

            "risk_score":
                "risk_score_baseline"
        }
    )

    comparison = updated_comparison.merge(
        baseline_comparison,
        on="dependency_id",
        how="left"
    )

    comparison[
        "risk_score_baseline"
    ] = pd.to_numeric(
        comparison[
            "risk_score_baseline"
        ],
        errors="coerce"
    ).fillna(0)

    comparison[
        "risk_score_updated"
    ] = pd.to_numeric(
        comparison[
            "risk_score_updated"
        ],
        errors="coerce"
    ).fillna(0)

    comparison[
        "cve_count_baseline"
    ] = pd.to_numeric(
        comparison[
            "cve_count_baseline"
        ],
        errors="coerce"
    ).fillna(0)

    comparison[
        "cve_count_updated"
    ] = pd.to_numeric(
        comparison[
            "cve_count_updated"
        ],
        errors="coerce"
    ).fillna(0)

    comparison[
        "risk_increase"
    ] = (
        comparison[
            "risk_score_updated"
        ]
        -
        comparison[
            "risk_score_baseline"
        ]
    ).round(1)

    comparison[
        "cve_count_increase"
    ] = (
        comparison[
            "cve_count_updated"
        ]
        -
        comparison[
            "cve_count_baseline"
        ]
    )

    exact_exposures = (
        find_exact_simulated_exposures(
            dependencies,
            simulated_feed
        )
    )

    if exact_exposures.empty:

        new_alerts = pd.DataFrame()

    else:

        new_alerts = comparison.merge(
            exact_exposures,
            on="dependency_id",
            how="inner"
        )

        new_alerts = (
            new_alerts.drop_duplicates(
                subset=[
                    "dependency_id"
                ]
            )
        )

    st.divider()

    st.header(
        "Live Alert Status"
    )

    alert1, alert2, alert3, alert4 = (
        st.columns(4)
    )

    alert1.metric(
        "Simulated CVEs",
        len(simulated_feed)
    )

    alert2.metric(
        "Exactly Affected Dependencies",
        len(new_alerts)
    )

    alert3.metric(
        "Affected Applications",
        (
            new_alerts[
                "app_id"
            ].nunique()
            if not new_alerts.empty
            else 0
        )
    )

    alert4.metric(
        "Critical Dependency Risks",
        (
            int(
                (
                    new_alerts[
                        "severity"
                    ]
                    .astype(str)
                    .str.lower()
                    == "critical"
                ).sum()
            )
            if not new_alerts.empty
            else 0
        )
    )

    if simulated_feed.empty:

        st.info(
            "Select affected versions and publish a "
            "simulated CVE to trigger an alert."
        )

    elif new_alerts.empty:

        st.warning(
            "The simulated CVE was published, but no "
            "installed dependency exactly matches the "
            "selected affected versions."
        )

    else:

        st.error(
            "New software supply-chain exposure detected!"
        )

        st.write(
            "These alerts are confirmed because both the "
            "library name and installed version match the "
            "simulated CVE."
        )

        alert_columns = [
            "app_name",
            "component",
            "version",
            "direct",
            "simulated_cve_ids",
            "vulnerability_status",
            "version_evidence",
            "risk_score_baseline",
            "risk_score_updated",
            "risk_increase",
            "severity",
            "patched_versions"
        ]

        available_alert_columns = [
            column
            for column in alert_columns
            if column in new_alerts.columns
        ]

        displayed_alerts = new_alerts[
            available_alert_columns
        ].sort_values(
            by="risk_score_updated",
            ascending=False
        )

        st.dataframe(
            displayed_alerts,
            width="stretch",
            hide_index=True
        )

        st.subheader(
            "Applications Requiring Attention"
        )

        affected_application_names = sorted(
            new_alerts[
                "app_name"
            ]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        for application_name in (
            affected_application_names
        ):

            st.write(
                f"🔴 {application_name}"
            )

        st.download_button(
            "Download Live CVE Alerts",
            data=new_alerts.to_csv(
                index=False
            ),
            file_name=(
                "chainguard_live_cve_alerts.csv"
            ),
            mime="text/csv"
        )

    if not simulated_feed.empty:

        st.divider()

        st.header(
            "Simulated Vulnerability Feed"
        )

        display_feed = simulated_feed.copy()

        display_feed[
            "affected_versions"
        ] = display_feed[
            "affected_versions"
        ].apply(
            lambda versions:
                ", ".join(
                    convert_versions_to_list(
                        versions
                    )
                )
        )

        st.dataframe(
            display_feed,
            width="stretch",
            hide_index=True
        )

        if st.button(
            "Reset Simulated CVEs",
            key="reset_official_live_cves"
        ):

            st.session_state[
                "simulated_vulnerabilities"
            ] = pd.DataFrame(
                columns=vulnerability_columns
            )

            st.rerun()

    st.caption(
        "Simulated CVEs exist only during the current "
        "dashboard session and do not modify the official "
        "vulnerability database."
    )


except Exception as error:

    st.error(
        f"Unable to run the official CVE simulation: "
        f"{error}"
    )