import logging
import time
from datetime import timedelta
from typing import Dict, List

import streamlit as st
from llm_guard.input_scanners import get_scanner_by_name
from llm_guard.input_scanners.anonymize import default_entity_types
from llm_guard.input_scanners.prompt_injection import ALL_MODELS as PI_ALL_MODELS
from llm_guard.vault import Vault
from streamlit_tags import st_tags

logger = logging.getLogger("llm-guard-playground")


def init_settings() -> (List, Dict):
    all_scanners = [
        "Anonymize",
        "BanSubstrings",
        "BanTopics",
        "Code",
        "Language",
        "PromptInjection",
        "Regex",
        "Secrets",
        "Sentiment",
        "TokenLimit",
        "Toxicity",
    ]

    st_enabled_scanners = st.sidebar.multiselect(
        "Select scanners",
        options=all_scanners,
        default=all_scanners,
        help="The list can be found here: https://laiyer-ai.github.io/llm-guard/input_scanners/anonymize/",
    )

    settings = {}

    if "Anonymize" in st_enabled_scanners:
        st_anon_expander = st.sidebar.expander(
            "Anonymize",
            expanded=False,
        )

        with st_anon_expander:
            st_anon_entity_types = st_tags(
                label="Anonymize entities",
                text="Type and press enter",
                value=default_entity_types,
                suggestions=default_entity_types
                + ["DATE_TIME", "NRP", "LOCATION", "MEDICAL_LICENSE", "US_PASSPORT"],
                maxtags=30,
                key="anon_entity_types",
            )
            st.caption(
                "Check all supported entities: https://llm-guard.com/input_scanners/anonymize/"
            )
            st_anon_hidden_names = st_tags(
                label="Hidden names to be anonymized",
                text="Type and press enter",
                value=[],
                suggestions=[],
                maxtags=30,
                key="anon_hidden_names",
            )
            st.caption("These names will be hidden e.g. [REDACTED_CUSTOM1].")
            st_anon_allowed_names = st_tags(
                label="Allowed names to ignore",
                text="Type and press enter",
                value=[],
                suggestions=[],
                maxtags=30,
                key="anon_allowed_names",
            )
            st.caption("These names will be ignored even if flagged by the detector.")
            st_anon_preamble = st.text_input(
                "Preamble", value="Text to prepend to sanitized prompt: "
            )
            st_anon_use_faker = st.checkbox(
                "Use Faker", value=False, help="Use Faker library to generate fake data"
            )
            st_anon_threshold = st.slider(
                label="Threshold",
                value=0.0,
                min_value=0.0,
                max_value=1.0,
                step=0.1,
                key="anon_threshold",
            )

        settings["Anonymize"] = {
            "entity_types": st_anon_entity_types,
            "hidden_names": st_anon_hidden_names,
            "allowed_names": st_anon_allowed_names,
            "preamble": st_anon_preamble,
            "use_faker": st_anon_use_faker,
            "threshold": st_anon_threshold,
        }

    if "BanSubstrings" in st_enabled_scanners:
        st_bs_expander = st.sidebar.expander(
            "Ban Substrings",
            expanded=False,
        )

        with st_bs_expander:
            st_bs_substrings = st.text_area(
                "Enter substrings to ban (one per line)",
                value="test\nhello\nworld",
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

        settings["BanTopics"] = {
            "topics": st_bt_topics,
            "threshold": st_bt_threshold,
        }

    if "Code" in st_enabled_scanners:
        st_cd_expander = st.sidebar.expander(
            "Code",
            expanded=False,
        )

        with st_cd_expander:
            st_cd_languages = st.multiselect(
                "Programming languages",
                ["python", "java", "javascript", "go", "php", "ruby"],
                default=["python"],
            )

            st_cd_mode = st.selectbox("Mode", ["allowed", "denied"], index=0)

        allowed_languages = None
        denied_languages = None
        if st_cd_mode == "allowed":
            allowed_languages = st_cd_languages
        elif st_cd_mode == "denied":
            denied_languages = st_cd_languages

        settings["Code"] = {
            "allowed": allowed_languages,
            "denied": denied_languages,
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

    if "PromptInjection" in st_enabled_scanners:
        st_pi_expander = st.sidebar.expander(
            "Prompt Injection",
            expanded=False,
        )

        with st_pi_expander:
            st_pi_threshold = st.slider(
                label="Threshold",
                value=0.75,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="prompt_injection_threshold",
            )

        settings["PromptInjection"] = {
            "threshold": st_pi_threshold,
        }

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

    if "Secrets" in st_enabled_scanners:
        st_sec_expander = st.sidebar.expander(
            "Secrets",
            expanded=False,
        )

        with st_sec_expander:
            st_sec_redact_mode = st.selectbox("Redact mode", ["all", "partial", "hash"])

        settings["Secrets"] = {
            "redact_mode": st_sec_redact_mode,
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

        settings["Sentiment"] = {
            "threshold": st_sent_threshold,
        }

    if "TokenLimit" in st_enabled_scanners:
        st_tl_expander = st.sidebar.expander(
            "Token Limit",
            expanded=False,
        )

        with st_tl_expander:
            st_tl_limit = st.number_input(
                "Limit", value=4096, min_value=0, max_value=10000, step=10
            )
            st_tl_encoding_name = st.selectbox(
                "Encoding name",
                ["cl100k_base", "p50k_base", "r50k_base"],
                index=0,
                help="Read more: https://github.com/openai/openai-cookbook/blob/main/examples/How_to_count_tokens_with_tiktoken.ipynb",
            )

        settings["TokenLimit"] = {
            "limit": st_tl_limit,
            "encoding_name": st_tl_encoding_name,
        }

    if "Toxicity" in st_enabled_scanners:
        st_tox_expander = st.sidebar.expander(
            "Toxicity",
            expanded=False,
        )

        with st_tox_expander:
            st_tox_threshold = st.slider(
                label="Threshold",
                value=0.75,
                min_value=0.0,
                max_value=1.0,
                step=0.05,
                key="toxicity_threshold",
            )

        settings["Toxicity"] = {
            "threshold": st_tox_threshold,
        }

    return st_enabled_scanners, settings


def get_scanner(scanner_name: str, vault: Vault, settings: Dict):
    logger.debug(f"Initializing {scanner_name} scanner")

    if scanner_name == "Anonymize":
        settings["vault"] = vault

    if scanner_name == "PromptInjection":
        settings["models"] = PI_ALL_MODELS

    if scanner_name in ["Anonymize", "BanTopics", "Code", "PromptInjection", "Toxicity"]:
        settings["use_onnx"] = True

    return get_scanner_by_name(scanner_name, settings)


def scan(
    vault: Vault, enabled_scanners: List[str], settings: Dict, text: str, fail_fast: bool = False
) -> (str, List[Dict[str, any]]):
    sanitized_prompt = text
    results = []

    status_text = "Scanning prompt..."
    if fail_fast:
        status_text = "Scanning prompt (fail fast mode)..."

    with st.status(status_text, expanded=True) as status:
        for scanner_name in enabled_scanners:
            st.write(f"{scanner_name} scanner...")
            scanner = get_scanner(scanner_name, vault, settings[scanner_name])

            start_time = time.monotonic()
            sanitized_prompt, is_valid, risk_score = scanner.scan(sanitized_prompt)
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

    return sanitized_prompt, results
