from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from analyzer import (
    load_data,
    analyze_dependencies
)


REVIEW_FOLDER = (
    Path(__file__).parent.parent
    / "review_data"
)

REVIEW_FOLDER.mkdir(
    exist_ok=True
)

FEEDBACK_FILE = (
    REVIEW_FOLDER
    / "analyst_feedback.csv"
)

FEEDBACK_COLUMNS = [
    "dependency_id",
    "app_name",
    "component",
    "version",
    "evidence_status",
    "decision",
    "analyst_comment",
    "reviewed_at"
]


def load_feedback():
    """Load saved analyst decisions."""

    if not FEEDBACK_FILE.exists():

        return pd.DataFrame(
            columns=FEEDBACK_COLUMNS
        )

    feedback = pd.read_csv(
        FEEDBACK_FILE
    )

    for column in FEEDBACK_COLUMNS:

        if column not in feedback.columns:
            feedback[column] = ""

    return feedback[
        FEEDBACK_COLUMNS
    ]


def save_feedback(new_feedback):
    """Save or update one analyst decision."""

    existing_feedback = (
        load_feedback()
    )

    existing_feedback = (
        existing_feedback[
            existing_feedback[
                "dependency_id"
            ]
            != new_feedback[
                "dependency_id"
            ]
        ]
    )

    updated_feedback = pd.concat(
        [
            existing_feedback,
            pd.DataFrame(
                [new_feedback]
            )
        ],
        ignore_index=True
    )

    updated_feedback.to_csv(
        FEEDBACK_FILE,
        index=False
    )


st.set_page_config(
    page_title="Analyst Review",
    page_icon="✅",
    layout="wide"
)

st.title("Analyst Review and Feedback")

st.write(
    "Review automated findings, confirm evidence, "
    "record exceptions and identify false positives."
)


try:
    data = load_data()

    results = analyze_dependencies(
        data
    )

    risky_results = results[
        (
            results[
                "vulnerability_status"
            ]
            != "none"
        )
        |
        (
            results["risk_score"]
            >= 25
        )
    ].copy()

    risky_results = (
        risky_results.sort_values(
            by="risk_score",
            ascending=False
        )
    )

    if risky_results.empty:

        st.success(
            "No findings currently require review."
        )

        st.stop()

    risky_results[
        "finding_name"
    ] = (
        risky_results[
            "dependency_id"
        ].astype(str)
        + " | "
        + risky_results[
            "app_name"
        ].astype(str)
        + " | "
        + risky_results[
            "component"
        ].astype(str)
        + " "
        + risky_results[
            "version"
        ].astype(str)
        + " | Score "
        + risky_results[
            "risk_score"
        ].astype(str)
    )

    # -------------------------------------
    # FINDING SELECTION
    # -------------------------------------

    st.header("Select a Finding")

    selected_finding_name = st.selectbox(
        "Finding",
        risky_results[
            "finding_name"
        ].tolist(),
        key="analyst_finding_selector"
    )

    selected_finding = risky_results[
        risky_results[
            "finding_name"
        ]
        == selected_finding_name
    ].iloc[0]

    # -------------------------------------
    # FINDING DETAILS
    # -------------------------------------

    st.subheader("Finding Details")

    detail1, detail2, detail3, detail4 = (
        st.columns(4)
    )

    detail1.metric(
        "Application",
        selected_finding[
            "app_name"
        ]
    )

    detail2.metric(
        "Component",
        selected_finding[
            "component"
        ]
    )

    detail3.metric(
        "Risk Score",
        selected_finding[
            "risk_score"
        ]
    )

    detail4.metric(
        "Severity",
        str(
            selected_finding[
                "severity"
            ]
        ).upper()
    )

    st.write(
        "**Dependency ID:**",
        selected_finding[
            "dependency_id"
        ]
    )

    st.write(
        "**Installed version:**",
        selected_finding[
            "version"
        ]
    )

    st.write(
        "**CVEs:**",
        (
            selected_finding[
                "cve_ids"
            ]
            if selected_finding[
                "cve_ids"
            ]
            else "No CVE"
        )
    )

    st.write(
        "**Vulnerability evidence:**",
        str(
            selected_finding[
                "vulnerability_status"
            ]
        ).upper()
    )

    st.write(
        "**Version evidence:**",
        selected_finding[
            "version_evidence"
        ]
    )

    if (
        selected_finding[
            "vulnerability_status"
        ]
        == "confirmed"
    ):

        st.error(
            "The installed version exactly matches "
            "affected_versions."
        )

    elif (
        selected_finding[
            "vulnerability_status"
        ]
        == "potential"
    ):

        st.warning(
            "The library has known CVEs, but this "
            "installed version is not listed as affected. "
            "Verify vendor advisories before confirming "
            "remediation."
        )

    st.write(
        "**Licence status:**",
        selected_finding[
            "license_status"
        ]
    )

    st.write(
        "**Maintenance status:**",
        selected_finding[
            "maintenance_status"
        ]
    )

    st.write(
        "**Risk explanation:**",
        selected_finding[
            "explanation"
        ]
    )

    st.divider()

    # -------------------------------------
    # ANALYST DECISION
    # -------------------------------------

    st.header("Analyst Decision")

    decision = st.selectbox(
        "Select a decision",
        [
            "Confirmed Risk",
            "Needs Version Verification",
            "False Positive",
            "Accepted Risk",
            "Patched Custom Build",
            "Not Reachable",
            "Remediated"
        ],
        key="analyst_decision_selector"
    )

    analyst_comment = st.text_area(
        "Analyst justification",
        placeholder=(
            "Explain why this decision "
            "was selected..."
        ),
        key="analyst_comment"
    )

    if st.button(
        "Save Analyst Decision",
        type="primary"
    ):

        if not analyst_comment.strip():

            st.warning(
                "Enter a justification "
                "before saving."
            )

        else:
            new_feedback = {
                "dependency_id":
                    selected_finding[
                        "dependency_id"
                    ],

                "app_name":
                    selected_finding[
                        "app_name"
                    ],

                "component":
                    selected_finding[
                        "component"
                    ],

                "version":
                    selected_finding[
                        "version"
                    ],

                "evidence_status":
                    selected_finding[
                        "vulnerability_status"
                    ],

                "decision":
                    decision,

                "analyst_comment":
                    analyst_comment.strip(),

                "reviewed_at":
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            save_feedback(
                new_feedback
            )

            st.success(
                "Analyst decision saved successfully!"
            )

    st.divider()

    # -------------------------------------
    # PREVIOUS REVIEWS
    # -------------------------------------

    st.header("Previous Analyst Decisions")

    feedback = load_feedback()

    if feedback.empty:

        st.info(
            "No analyst decisions have "
            "been recorded."
        )

    else:
        review1, review2, review3, review4 = (
            st.columns(4)
        )

        review1.metric(
            "Reviewed Findings",
            len(feedback)
        )

        review2.metric(
            "Needs Verification",
            int(
                (
                    feedback["decision"]
                    == "Needs Version Verification"
                ).sum()
            )
        )

        review3.metric(
            "False Positives",
            int(
                (
                    feedback["decision"]
                    == "False Positive"
                ).sum()
            )
        )

        review4.metric(
            "Remediated",
            int(
                (
                    feedback["decision"]
                    == "Remediated"
                ).sum()
            )
        )

        st.dataframe(
            feedback,
            width="stretch",
            hide_index=True
        )

        st.download_button(
            "Download Feedback CSV",
            data=feedback.to_csv(
                index=False
            ),
            file_name=(
                "analyst_feedback.csv"
            ),
            mime="text/csv"
        )


except Exception as error:

    st.error(
        f"Unable to open analyst review: {error}"
    )