import logging
import time
from datetime import timedelta
from typing import Dict, List

import streamlit as st
from llm_guard.input_scanners.anonymize import default_entity_types
from llm_guard.output_scanners import get_scanner_by_name
from llm_guard.output_scanners.relevance import all_models as relevance_models
from llm_guard.vault import Vault
from streamlit_tags import st_tags

logger = logging.getLogger("llm-guard-playground")


def init_settings() -> (List, Dict):
    all_scanners = [
        "BanSubstrings",
        "BanTopics",
        "Bias",
        "Code",
        "Deanonymize",
        "JSON",
        "Language",
        "LanguageSame",
        "MaliciousURLs",
        "NoRefusal",
        "FactualConsistency",
        "Regex",
        "Relevance",
        "Sensitive",
        "Sentiment",
        "Toxicity",
    ]

    st_enabled_scanners = st.sidebar.multiselect(
        "Select scanners",
        options=all_scanners,
        default=all_scanners,
        help="The list can be found here: https://laiyer-ai.github.io/llm-guard/output_scanners/bias/",
    )

    settings = {}

    if "BanSubstrings" in st_enabled_scanners:
        st_bs_expander = st.sidebar.expander(
            "Ban Substrings",
            expanded=False,
        )

        with st_bs_expander:
            st_bs_substrings = st.text_area(
                "Enter substrings to ban (one per line)",
                value="test\nhello\nworld\n",
                height=200,
            ).split("\n")

            st_bs_match_type = st.selectbox("Match type", ["str", "word"])
            st_bs_case_sensitive = st.checkbox("Case sensitive", value=False)
            st_bs_redact = st.checkbox("Redact", value=False)
            st_bs_contains_all = st.checkbox("Contains all", value=False)

        settings["BanSubstrings"] = {
            "substrings": st_bs_substrings,
            "match_type": st_bs_match_type,
            "case_sensitive": st_bs_case_sensitive,
            "redact": st_bs_redact,
            "contains_all": st_bs_contains_all,
        }

    if "BanTopics" in st_enabled_scanners:
        st_bt_expander = st.sidebar.expander(
            "Ban Topics",
            expanded=False,
        )

        with st_bt_expander:
            st_bt_topics = st_tags(
                label="List of topics",
                text="Type and press enter",
                value=["violence"],
                suggestions=[],
                maxtags=30,
                key="bt_topics",
            )

            st_bt_threshold = st.slider(
                label="Threshold",
                value=0.6,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="ban_topics_threshold",
            )

        settings["BanTopics"] = {"topics": st_bt_topics, "threshold": st_bt_threshold}

    if "Bias" in st_enabled_scanners:
        st_bias_expander = st.sidebar.expander(
            "Bias",
            expanded=False,
        )

        with st_bias_expander:
            st_bias_threshold = st.slider(
                label="Threshold",
                value=0.75,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="bias_threshold",
            )

        settings["Bias"] = {"threshold": st_bias_threshold}

    if "Code" in st_enabled_scanners:
        st_cd_expander = st.sidebar.expander(
            "Code",
            expanded=False,
        )

        with st_cd_expander:
            st_cd_languages = st.multiselect(
                "Programming languages",
                options=["python", "java", "javascript", "go", "php", "ruby"],
                default=["python"],
            )

            st_cd_mode = st.selectbox("Mode", ["allowed", "denied"], index=0)

        allowed_languages = None
        denied_languages = None
        if st_cd_mode == "allowed":
            allowed_languages = st_cd_languages
        elif st_cd_mode == "denied":
            denied_languages = st_cd_languages

        settings["Code"] = {"allowed": allowed_languages, "denied": denied_languages}

    if "JSON" in st_enabled_scanners:
        st_json_expander = st.sidebar.expander(
            "JSON",
            expanded=False,
        )

        with st_json_expander:
            st_json_required_elements = st.slider(
                label="Required elements",
                value=0,
                min_value=0,
                max_value=10,
                step=1,
                key="json_required_elements",
                help="The minimum number of JSON elements that should be present",
            )

            st_json_repair = st.checkbox("Repair", value=False, help="Attempt to repair the JSON")

        settings["JSON"] = {
            "required_elements": st_json_required_elements,
            "repair": st_json_repair,
        }

    if "Language" in st_enabled_scanners:
        st_lan_expander = st.sidebar.expander(
            "Language",
            expanded=False,
        )

        with st_lan_expander:
            st_lan_valid_language = st.multiselect(
                "Languages",
                [
                    "ar",
                    "bg",
                    "de",
                    "el",
                    "en",
                    "es",
                    "fr",
                    "hi",
                    "it",
                    "ja",
                    "nl",
                    "pl",
                    "pt",
                    "ru",
                    "sw",
                    "th",
                    "tr",
                    "ur",
                    "vi",
                    "zh",
                ],
                default=["en"],
            )

        settings["Language"] = {
            "valid_languages": st_lan_valid_language,
        }

    if "MaliciousURLs" in st_enabled_scanners:
        st_murls_expander = st.sidebar.expander(
            "Malicious URLs",
            expanded=False,
        )

        with st_murls_expander:
            st_murls_threshold = st.slider(
                label="Threshold",
                value=0.75,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="murls_threshold",
            )

        settings["MaliciousURLs"] = {"threshold": st_murls_threshold}

    if "NoRefusal" in st_enabled_scanners:
        st_no_ref_expander = st.sidebar.expander(
            "No refusal",
            expanded=False,
        )

        with st_no_ref_expander:
            st_no_ref_threshold = st.slider(
                label="Threshold",
                value=0.5,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="no_ref_threshold",
            )

        settings["NoRefusal"] = {"threshold": st_no_ref_threshold}

    if "FactualConsistency" in st_enabled_scanners:
        st_fc_expander = st.sidebar.expander(
            "FactualConsistency",
            expanded=False,
        )

        with st_fc_expander:
            st_fc_minimum_score = st.slider(
                label="Minimum score",
                value=0.5,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="fc_threshold",
            )

        settings["FactualConsistency"] = {"minimum_score": st_fc_minimum_score}

    if "Regex" in st_enabled_scanners:
        st_regex_expander = st.sidebar.expander(
            "Regex",
            expanded=False,
        )

        with st_regex_expander:
            st_regex_patterns = st.text_area(
                "Enter patterns to ban (one per line)",
                value="Bearer [A-Za-z0-9-._~+/]+",
                height=200,
            ).split("\n")

            st_regex_type = st.selectbox(
                "Match type",
                ["good", "bad"],
                index=1,
                help="good: allow only good patterns, bad: ban bad patterns",
            )

            st_redact = st.checkbox(
                "Redact", value=False, help="Replace the matched bad patterns with [REDACTED]"
            )

        good_patterns = None
        bad_patterns = None
        if st_regex_type == "good":
            good_patterns = st_regex_patterns
        elif st_regex_type == "bad":
            bad_patterns = st_regex_patterns

        settings["Regex"] = {
            "good_patterns": good_patterns,
            "bad_patterns": bad_patterns,
            "redact": st_redact,
        }

    if "Relevance" in st_enabled_scanners:
        st_rele_expander = st.sidebar.expander(
            "Relevance",
            expanded=False,
        )

        with st_rele_expander:
            st_rele_threshold = st.slider(
                label="Threshold",
                value=0.5,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="rele_threshold",
            )

            st_rele_model = st.selectbox("Embeddings model", relevance_models, index=1)

        settings["Relevance"] = {"threshold": st_rele_threshold, "model": st_rele_model}

    if "Sensitive" in st_enabled_scanners:
        st_sens_expander = st.sidebar.expander(
            "Sensitive",
            expanded=False,
        )

        with st_sens_expander:
            st_sens_entity_types = st_tags(
                label="Sensitive entities",
                text="Type and press enter",
                value=default_entity_types,
                suggestions=default_entity_types
                + ["DATE_TIME", "NRP", "LOCATION", "MEDICAL_LICENSE", "US_PASSPORT"],
                maxtags=30,
                key="sensitive_entity_types",
            )
            st.caption(
                "Check all supported entities: https://llm-guard.com/input_scanners/anonymize/"
            )
            st_sens_redact = st.checkbox("Redact", value=False, key="sens_redact")
            st_sens_threshold = st.slider(
                label="Threshold",
                value=0.0,
                min_value=0.0,
                max_value=1.0,
                step=0.1,
                key="sens_threshold",
            )

        settings["Sensitive"] = {
            "entity_types": st_sens_entity_types,
            "redact": st_sens_redact,
            "threshold": st_sens_threshold,
        }

    if "Sentiment" in st_enabled_scanners:
        st_sent_expander = st.sidebar.expander(
            "Sentiment",
            expanded=False,
        )

        with st_sent_expander:
            st_sent_threshold = st.slider(
                label="Threshold",
                value=-0.1,
                min_value=-1.0,
                max_value=1.0,
                step=0.1,
                key="sentiment_threshold",
                help="Negative values are negative sentiment, positive values are positive sentiment",
            )

        settings["Sentiment"] = {"threshold": st_sent_threshold}

    if "Toxicity" in st_enabled_scanners:
        st_tox_expander = st.sidebar.expander(
            "Toxicity",
            expanded=False,
        )

        with st_tox_expander:
            st_tox_threshold = st.slider(
                label="Threshold",
                value=0.0,
                min_value=-1.0,
                max_value=1.0,
                step=0.05,
                key="toxicity_threshold",
                help="A negative value (closer to 0 as the label output) indicates toxicity in the text, while a positive logit (closer to 1 as the label output) suggests non-toxicity.",
            )

        settings["Toxicity"] = {"threshold": st_tox_threshold}

    return st_enabled_scanners, settings


def get_scanner(scanner_name: str, vault: Vault, settings: Dict):
    logger.debug(f"Initializing {scanner_name} scanner")

    if scanner_name == "Deanonymize":
        settings["vault"] = vault

    if scanner_name in [
        "BanTopics",
        "Bias",
        "Code",
        "Language",
        "LanguageSame",
        "MaliciousURLs",
        "NoRefusal",
        "FactualConsistency",
        "Relevance",
        "Sensitive",
        "Toxicity",
    ]:
        settings["use_onnx"] = True

    return get_scanner_by_name(scanner_name, settings)


def scan(
    vault: Vault,
    enabled_scanners: List[str],
    settings: Dict,
    prompt: str,
    text: str,
    fail_fast: bool = False,
) -> (str, List[Dict[str, any]]):
    sanitized_output = text
    results = []

    status_text = "Scanning prompt..."
    if fail_fast:
        status_text = "Scanning prompt (fail fast mode)..."

    with st.status(status_text, expanded=True) as status:
        for scanner_name in enabled_scanners:
            st.write(f"{scanner_name} scanner...")
            scanner = get_scanner(
                scanner_name, vault, settings[scanner_name] if scanner_name in settings else {}
            )

            start_time = time.monotonic()
            sanitized_output, is_valid, risk_score = scanner.scan(prompt, sanitized_output)
            end_time = time.monotonic()

            results.append(
                {
                    "scanner": scanner_name,
                    "is_valid": is_valid,
                    "risk_score": risk_score,
                    "took_sec": round(timedelta(seconds=end_time - start_time).total_seconds(), 2),
                }
            )

            if fail_fast and not is_valid:
                break

        status.update(label="Scanning complete", state="complete", expanded=False)

    return sanitized_output, results
