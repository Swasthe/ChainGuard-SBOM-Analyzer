import plotly.graph_objects as go
import streamlit as st

from analyzer import (
    load_data,
    analyze_dependencies
)

from correlation_engine import (
    find_shared_risks,
    simulate_component_fix
)


st.set_page_config(
    page_title="Organization Risk",
    page_icon="🌐",
    layout="wide"
)

st.title("Organization-Wide Supply Chain Risk")

st.write(
    "Identify risky components shared across "
    "multiple enterprise applications."
)


try:
    data = load_data()

    results = analyze_dependencies(
        data
    )

    shared_risks = find_shared_risks(
        results
    )

    if shared_risks.empty:

        st.success(
            "No risky component is shared by "
            "multiple applications."
        )

    else:
        # -------------------------------------
        # ORGANIZATION METRICS
        # -------------------------------------

        affected_applications = set()

        for names in shared_risks[
            "application_names"
        ]:

            for name in str(names).split(","):

                cleaned_name = name.strip()

                if cleaned_name:
                    affected_applications.add(
                        cleaned_name
                    )

        critical_shared = int(
            (
                shared_risks[
                    "highest_severity"
                ]
                == "critical"
            ).sum()
        )

        confirmed_shared = int(
            (
                shared_risks[
                    "evidence_status"
                ]
                == "confirmed"
            ).sum()
        )

        potential_shared = int(
            (
                shared_risks[
                    "evidence_status"
                ]
                == "potential"
            ).sum()
        )

        metric1, metric2, metric3 = (
            st.columns(3)
        )

        metric1.metric(
            "Shared Risky Components",
            len(shared_risks)
        )

        metric2.metric(
            "Affected Applications",
            len(affected_applications)
        )

        metric3.metric(
            "Critical Shared Components",
            critical_shared
        )

        metric4, metric5 = st.columns(2)

        metric4.metric(
            "Confirmed Shared CVE Risks",
            confirmed_shared
        )

        metric5.metric(
            "Potential Shared CVE Risks",
            potential_shared
        )

        if potential_shared > 0:

            st.warning(
                f"{potential_shared} shared components "
                "have library-level CVE evidence, but "
                "their installed versions are not listed "
                "in affected_versions."
            )

        st.divider()

        # -------------------------------------
        # SHARED-RISK TABLE
        # -------------------------------------

        st.header("Shared Component Risks")

        table_columns = [
            "component",
            "affected_applications",
            "application_names",
            "installed_versions",
            "evidence_status",
            "confirmed_findings",
            "potential_findings",
            "maximum_risk_score",
            "highest_severity",
            "total_findings",
            "cve_count"
        ]

        st.dataframe(
            shared_risks[
                table_columns
            ],
            width="stretch",
            hide_index=True
        )

        st.divider()

        # -------------------------------------
        # SHARED-RISK CHART
        # -------------------------------------

        st.header("Most Widely Shared Risks")

        chart_data = shared_risks.head(
            10
        ).copy()

        bar_chart = go.Figure(
            data=[
                go.Bar(
                    x=chart_data[
                        "affected_applications"
                    ],
                    y=chart_data[
                        "component"
                    ],
                    orientation="h",
                    marker=dict(
                        color=chart_data[
                            "maximum_risk_score"
                        ],
                        colorscale=[
                            [0, "#22C55E"],
                            [0.5, "#F59E0B"],
                            [1, "#EF4444"]
                        ],
                        colorbar=dict(
                            title="Risk Score"
                        )
                    ),
                    text=chart_data[
                        "affected_applications"
                    ],
                    textposition="outside",
                    hovertemplate=(
                        "<b>%{y}</b><br>"
                        "Applications affected: %{x}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        bar_chart.update_layout(
            xaxis_title=(
                "Number of Applications"
            ),
            yaxis_title="Component",
            height=500,
            margin=dict(
                l=40,
                r=40,
                t=30,
                b=40
            )
        )

        st.plotly_chart(
            bar_chart,
            width="stretch"
        )

        st.divider()

        # -------------------------------------
        # WHAT-IF SIMULATOR
        # -------------------------------------

        st.header("What-If Remediation Simulator")

        st.write(
            "Select a shared component to estimate "
            "how much organizational risk could be "
            "reduced if its vulnerability contribution "
            "were removed."
        )

        selected_component = st.selectbox(
            "Select a component",
            shared_risks[
                "component"
            ].tolist(),
            key="organization_component_selector"
        )

        simulation = simulate_component_fix(
            results,
            selected_component
        )

        if simulation:

            evidence_status = simulation[
                "evidence_status"
            ]

            if evidence_status == "confirmed":

                st.error(
                    "Confirmed evidence: at least one "
                    "installed version exactly matches "
                    "affected_versions."
                )

            elif evidence_status == "potential":

                st.warning(
                    "Potential evidence: this library "
                    "has known CVEs, but the installed "
                    "versions are not listed in "
                    "affected_versions. Verification is "
                    "required before applying a fix."
                )

            else:

                st.info(
                    "No vulnerability evidence exists. "
                    "The component may be listed because "
                    "of licence or maintenance risk."
                )

            before_score = simulation[
                "current_average_score"
            ]

            after_score = simulation[
                "simulated_average_score"
            ]

            score_reduction = simulation[
                "estimated_score_reduction"
            ]

            critical_removed = (
                simulation[
                    "critical_before"
                ]
                -
                simulation[
                    "critical_after"
                ]
            )

            sim1, sim2, sim3, sim4 = (
                st.columns(4)
            )

            sim1.metric(
                "Applications Affected",
                simulation[
                    "affected_applications"
                ]
            )

            sim2.metric(
                "Average Risk Before",
                before_score
            )

            sim3.metric(
                "Average Risk After",
                after_score,
                delta=-score_reduction
            )

            sim4.metric(
                "Critical Findings Removed",
                critical_removed
            )

            comparison_chart = go.Figure(
                data=[
                    go.Bar(
                        x=[
                            "Before Simulation",
                            "After Simulation"
                        ],
                        y=[
                            before_score,
                            after_score
                        ],
                        marker_color=[
                            "#EF4444",
                            "#22C55E"
                        ],
                        text=[
                            before_score,
                            after_score
                        ],
                        textposition="outside"
                    )
                ]
            )

            comparison_chart.update_layout(
                title=(
                    "Estimated Impact of Addressing "
                    f"{selected_component}"
                ),
                yaxis_title="Average Risk Score",
                yaxis_range=[0, 100],
                height=450,
                showlegend=False
            )

            st.plotly_chart(
                comparison_chart,
                width="stretch"
            )

            st.subheader(
                "Affected Applications"
            )

            for application_name in simulation[
                "application_names"
            ]:

                st.write(
                    f"• {application_name}"
                )

            st.info(
                "This is a what-if estimate, not an "
                "actual software upgrade. For confirmed "
                "evidence, it simulates applying a valid "
                "patch. For potential evidence, it shows "
                "the benefit only if later verification "
                "proves the installed version is affected. "
                "Licence, maintenance and business-context "
                "risks remain in the score."
            )


except Exception as error:

    st.error(
        "Unable to generate organization-wide "
        f"risk analysis: {error}"
    )
