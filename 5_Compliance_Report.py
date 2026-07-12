from datetime import datetime

import pandas as pd
import streamlit as st

from analyzer import (
    load_data,
    analyze_dependencies
)


def create_compliance_findings(results):
    """Map detected risks to compliance guidance."""

    findings = []

    for _, row in results.iterrows():

        vulnerability_status = row[
            "vulnerability_status"
        ]

        # -------------------------------------
        # CONFIRMED VULNERABILITY
        # -------------------------------------

        if vulnerability_status == "confirmed":

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        "Confirmed vulnerability",

                    "evidence_status":
                        "confirmed",

                    "framework":
                        "OWASP",

                    "control":
                        (
                            "A06 – Vulnerable and "
                            "Outdated Components"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        (
                            "Apply the verified patch "
                            "or upgrade to a fixed version."
                        )
                }
            )

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        "Confirmed vulnerability",

                    "evidence_status":
                        "confirmed",

                    "framework":
                        "NIST",

                    "control":
                        (
                            "CM-8 – System Component "
                            "Inventory and Vulnerability "
                            "Management"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        (
                            "Track the affected component "
                            "and verify remediation."
                        )
                }
            )

        # -------------------------------------
        # POTENTIAL VULNERABILITY
        # -------------------------------------

        elif vulnerability_status == "potential":

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        (
                            "Potential vulnerability "
                            "requiring version verification"
                        ),

                    "evidence_status":
                        "potential",

                    "framework":
                        "OWASP",

                    "control":
                        (
                            "A06 – Vulnerable and "
                            "Outdated Components"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        (
                            "Verify the installed version "
                            "against vendor advisories "
                            "before confirming remediation."
                        )
                }
            )

        # -------------------------------------
        # LICENCE RISK
        # -------------------------------------

        if row["license_status"] in {
            "conflict",
            "unknown",
            "conditional"
        }:

            if (
                row["license_status"]
                == "conflict"
            ):

                licence_finding = (
                    "Licence incompatibility"
                )

                licence_recommendation = (
                    "Replace the component, obtain "
                    "an alternative licence or request "
                    "formal legal review."
                )

            elif (
                row["license_status"]
                == "unknown"
            ):

                licence_finding = (
                    "Unknown licence"
                )

                licence_recommendation = (
                    "Identify the licence and complete "
                    "a legal compatibility review."
                )

            else:

                licence_finding = (
                    "Conditional licence obligations"
                )

                licence_recommendation = (
                    "Review linking, modification and "
                    "distribution obligations."
                )

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        licence_finding,

                    "evidence_status":
                        row["license_status"],

                    "framework":
                        "NIST",

                    "control":
                        (
                            "SC-2 – Supplier and "
                            "Third-Party Assessment"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        licence_recommendation
                }
            )

        # -------------------------------------
        # MAINTENANCE RISK
        # -------------------------------------

        if (
            row["maintenance_status"]
            == "unmaintained"
        ):

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        "Unmaintained dependency",

                    "evidence_status":
                        "confirmed",

                    "framework":
                        "OpenSSF",

                    "control":
                        (
                            "Maintained Project "
                            "Indicators"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        (
                            "Migrate to an actively "
                            "maintained component or "
                            "document compensating controls."
                        )
                }
            )

        # -------------------------------------
        # TRANSITIVE RISK
        # -------------------------------------

        if (
            str(row["direct"]).lower()
            == "no"
            and vulnerability_status
            != "none"
        ):

            findings.append(
                {
                    "app_name":
                        row["app_name"],

                    "component":
                        row["component"],

                    "version":
                        row["version"],

                    "finding":
                        (
                            "Hidden transitive "
                            f"{vulnerability_status} risk"
                        ),

                    "evidence_status":
                        vulnerability_status,

                    "framework":
                        "Executive Order 14028",

                    "control":
                        (
                            "SBOM and Software "
                            "Supply-Chain Transparency"
                        ),

                    "severity":
                        row["severity"],

                    "risk_score":
                        row["risk_score"],

                    "recommendation":
                        (
                            "Trace the parent dependency "
                            "and remediate through the "
                            "appropriate upgrade path."
                        )
                }
            )

    return pd.DataFrame(findings)


def create_html_report(
    results,
    compliance_findings
):
    """Generate an HTML audit report."""

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
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
            results["severity"]
            == "critical"
        ).sum()
    )

    highest_risks = (
        results.sort_values(
            "risk_score",
            ascending=False
        )
        [
            [
                "app_name",
                "component",
                "version",
                "vulnerability_status",
                "cve_ids",
                "version_evidence",
                "license_status",
                "maintenance_status",
                "risk_score",
                "severity",
                "explanation"
            ]
        ]
        .head(30)
    )

    html = f"""
    <html>
    <head>
        <title>ChainGuard Risk Report</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                color: #1e293b;
            }}

            h1, h2 {{
                color: #0f172a;
            }}

            .summary {{
                background: #f1f5f9;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 25px;
            }}

            .warning {{
                background: #fff7ed;
                border-left: 5px solid #f59e0b;
                padding: 15px;
                margin-bottom: 25px;
            }}

            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 30px;
                font-size: 12px;
            }}

            th, td {{
                border: 1px solid #cbd5e1;
                padding: 8px;
                text-align: left;
            }}

            th {{
                background: #0f172a;
                color: white;
            }}
        </style>
    </head>

    <body>
        <h1>
            ChainGuard Software Supply-Chain
            Risk Report
        </h1>

        <p>Generated: {generated_at}</p>

        <div class="summary">
            <h2>Executive Summary</h2>

            <p>
                Dependencies analysed:
                {len(results)}
            </p>

            <p>
                Confirmed vulnerabilities:
                {confirmed_count}
            </p>

            <p>
                Potential vulnerabilities:
                {potential_count}
            </p>

            <p>
                Licence conflicts:
                {licence_conflicts}
            </p>

            <p>
                Unmaintained dependencies:
                {unmaintained_count}
            </p>

            <p>
                Critical findings:
                {critical_count}
            </p>
        </div>

        <div class="warning">
            Potential vulnerabilities identify
            libraries with known CVEs whose installed
            versions are not listed in
            affected_versions. They require verification
            and are not presented as confirmed exposure.
        </div>

        <h2>Highest-Risk Findings</h2>

        {highest_risks.to_html(index=False)}

        <h2>Compliance Guidance</h2>

        {
            compliance_findings.head(
                150
            ).to_html(index=False)
        }

        <p>
            This prototype uses official sample data,
            including documented version-evidence
            inconsistencies. Framework mappings provide
            guidance only and do not constitute formal
            legal or compliance certification.
        </p>
    </body>
    </html>
    """

    return html


st.set_page_config(
    page_title="Compliance Report",
    page_icon="📋",
    layout="wide"
)

st.title("Compliance Gap Analysis")

st.write(
    "Map confirmed and potential supply-chain "
    "risks to NIST, OWASP, OpenSSF and "
    "SBOM guidance."
)


try:
    data = load_data()

    results = analyze_dependencies(
        data
    )

    compliance_findings = (
        create_compliance_findings(
            results
        )
    )

    if compliance_findings.empty:

        st.success(
            "No compliance guidance findings "
            "were generated."
        )

    else:
        confirmed_findings = int(
            (
                compliance_findings[
                    "evidence_status"
                ]
                == "confirmed"
            ).sum()
        )

        potential_findings = int(
            (
                compliance_findings[
                    "evidence_status"
                ]
                == "potential"
            ).sum()
        )

        metric1, metric2, metric3, metric4 = (
            st.columns(4)
        )

        metric1.metric(
            "Compliance Findings",
            len(compliance_findings)
        )

        metric2.metric(
            "Applications Affected",
            compliance_findings[
                "app_name"
            ].nunique()
        )

        metric3.metric(
            "Confirmed Evidence",
            confirmed_findings
        )

        metric4.metric(
            "Potential Evidence",
            potential_findings
        )

        st.divider()

        # -------------------------------------
        # FILTERS
        # -------------------------------------

        filter1, filter2 = st.columns(2)

        with filter1:

            selected_framework = (
                st.selectbox(
                    "Framework",
                    [
                        "All"
                    ]
                    + sorted(
                        compliance_findings[
                            "framework"
                        ]
                        .dropna()
                        .unique()
                        .tolist()
                    ),
                    key=(
                        "compliance_framework_filter"
                    )
                )
            )

        with filter2:

            selected_evidence = (
                st.selectbox(
                    "Evidence status",
                    [
                        "All"
                    ]
                    + sorted(
                        compliance_findings[
                            "evidence_status"
                        ]
                        .dropna()
                        .unique()
                        .tolist()
                    ),
                    key=(
                        "compliance_evidence_filter"
                    )
                )
            )

        filtered_findings = (
            compliance_findings.copy()
        )

        if selected_framework != "All":

            filtered_findings = (
                filtered_findings[
                    filtered_findings[
                        "framework"
                    ]
                    == selected_framework
                ]
            )

        if selected_evidence != "All":

            filtered_findings = (
                filtered_findings[
                    filtered_findings[
                        "evidence_status"
                    ]
                    == selected_evidence
                ]
            )

        st.header("Compliance Findings")

        st.dataframe(
            filtered_findings.sort_values(
                "risk_score",
                ascending=False
            ),
            width="stretch",
            hide_index=True
        )

        st.divider()

        # -------------------------------------
        # APPLICATION SUMMARY
        # -------------------------------------

        st.header(
            "Application Compliance Summary"
        )

        application_summary = (
            compliance_findings.groupby(
                "app_name"
            )
            .agg(
                compliance_gaps=(
                    "finding",
                    "count"
                ),

                frameworks_affected=(
                    "framework",
                    "nunique"
                ),

                maximum_risk_score=(
                    "risk_score",
                    "max"
                ),

                potential_evidence=(
                    "evidence_status",
                    lambda values:
                        sum(
                            str(value)
                            == "potential"
                            for value in values
                        )
                )
            )
            .reset_index()
            .sort_values(
                "maximum_risk_score",
                ascending=False
            )
        )

        st.dataframe(
            application_summary,
            width="stretch",
            hide_index=True
        )

        st.divider()

        # -------------------------------------
        # REPORT EXPORT
        # -------------------------------------

        st.header("Export Audit Report")

        html_report = create_html_report(
            results,
            compliance_findings
        )

        download1, download2 = (
            st.columns(2)
        )

        with download1:

            st.download_button(
                "Download Compliance CSV",
                data=(
                    compliance_findings
                    .to_csv(
                        index=False
                    )
                ),
                file_name=(
                    "chainguard_compliance_findings.csv"
                ),
                mime="text/csv"
            )

        with download2:

            st.download_button(
                "Download HTML Audit Report",
                data=html_report,
                file_name=(
                    "chainguard_audit_report.html"
                ),
                mime="text/html"
            )

        st.warning(
            "Framework mappings are prototype-level "
            "guidance. Potential evidence requires "
            "verification and does not constitute a "
            "confirmed vulnerability or compliance "
            "violation."
        )


except Exception as error:

    st.error(
        "Unable to generate the compliance "
        f"report: {error}"
    )