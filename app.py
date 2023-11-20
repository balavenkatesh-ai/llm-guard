import logging
import os
import traceback

import pandas as pd
import streamlit as st
from llm_guard.vault import Vault
from streamlit.components.v1 import html

from output import init_settings as init_output_settings
from output import scan as scan_output
from prompt import init_settings as init_prompt_settings
from prompt import scan as scan_prompt
from msbr_llm_v1 import run_llama_model

def add_google_analytics(ga4_id):
    """
    Add Google Analytics 4 to a Streamlit app
    """
    ga_code = f"""
    <script async src="https://www.googletagmanager.com/gtag/js?id={ga4_id}"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){{dataLayer.push(arguments);}}
      gtag('js', new Date());
      gtag('config', '{ga4_id}');
    </script>
    """

    html(ga_code)


def show_scanning_report(st_is_valid,st_result_text,st_analysis):
    if st_is_valid is not None:
        st.subheader(f"Results - {'valid' if st_is_valid else 'invalid'}")

        col1, col2 = st.columns(2)

        with col1:
            st.text_area(label="Sanitized text", value=st_result_text, height=400)

        with col2:
            st.table(pd.DataFrame(st_analysis))


PROMPT = "prompt"
OUTPUT = "output"
vault = Vault()

st.set_page_config(
    page_title="LLM Guard Playground",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": "https://laiyer-ai.github.io/llm-guard/",
    },
)

logger = logging.getLogger("llm-guard-playground")
logger.setLevel(logging.INFO)


scanner_type = st.sidebar.selectbox("Type", [PROMPT, OUTPUT], index=0)

st_fail_fast = st.sidebar.checkbox(
    "Fail fast", value=False, help="Stop scanning after first failure"
)

enabled_scanners = None
settings = None
if scanner_type == PROMPT:
    enabled_scanners, settings = init_prompt_settings()
elif scanner_type == OUTPUT:
    enabled_scanners, settings = init_output_settings()

add_google_analytics("G-0HBVNHEZBW")

# Main pannel
st.subheader("Guard Prompt" if scanner_type == PROMPT else "Guard Output")
with st.expander("About", expanded=False):
    st.info(
        """LLM-Guard is a comprehensive tool designed to fortify the security of Large Language Models (LLMs).
        \n\n[Code](https://github.com/laiyer-ai/llm-guard) |
        [Documentation](https://laiyer-ai.github.io/llm-guard/)"""
    )

    st.markdown(
        "[![Pypi Downloads](https://img.shields.io/pypi/dm/llm-guard.svg)](https://img.shields.io/pypi/dm/llm-guard.svg)"  # noqa
        "[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)"
        "![GitHub Repo stars](https://img.shields.io/github/stars/laiyer-ai/llm-guard?style=social)"
    )

analyzer_load_state = st.info("Starting LLM Guard...")

analyzer_load_state.empty()

# Before:
prompt_examples_folder = "./examples/prompt"
output_examples_folder = "./examples/output"
prompt_examples = [f for f in os.listdir(prompt_examples_folder) if f.endswith(".txt")]
output_examples = [f for f in os.listdir(output_examples_folder) if f.endswith(".txt")]

if scanner_type == PROMPT:
    st_prompt_example = st.selectbox("Select prompt example", prompt_examples, index=0)

    with open(os.path.join(prompt_examples_folder, st_prompt_example), "r") as file:
        prompt_example_text = file.read()

    st_prompt_text = st.text_area(
        label="Enter prompt", value=prompt_example_text, height=200, key="prompt_text_input"
    )
    
    component_name = st.text_input("Enter your Threat Component Name:")
    component_version = st.text_input("Enter your Threat Component Version:")
    
elif scanner_type == OUTPUT:
    col1, col2 = st.columns(2)

    st_prompt_example = col1.selectbox("Select prompt example", prompt_examples, index=0)

    with open(os.path.join(prompt_examples_folder, st_prompt_example), "r") as file:
        prompt_example_text = file.read()

    st_prompt_text = col1.text_area(
        label="Enter prompt", value=prompt_example_text, height=300, key="prompt_text_input"
    )
    
    component_name = st.text_input("Enter your Threat Component Name:")
    component_version = st.text_input("Enter your Threat Component Version:")

    # st_output_example = col2.selectbox("Select output example", output_examples, index=0)

    # with open(os.path.join(output_examples_folder, st_output_example), "r") as file:
    #     output_example_text = file.read()
    # st_output_text = col2.text_area(
    #     label="Enter output", value=output_example_text, height=300, key="output_text_input"
    # )

st_result_text = None
st_analysis = None
st_is_valid = None

try:
    with st.form("text_form", clear_on_submit=False):
        submitted = st.form_submit_button("Scan Model Response")
        if submitted:
            results = {}
            st_output_text = run_llama_model(st_prompt_text,component_name,component_version)
            st_result_text, results = scan_output(
                vault, enabled_scanners, settings, st_prompt_text, st_output_text, st_fail_fast
            )
            st_is_valid = all(item["is_valid"] for item in results)
            show_scanning_report(st_is_valid,st_result_text,results)
            
    with st.form("text_form", clear_on_submit=False):
        submitted = st.form_submit_button("Scan Prompt Input")
        if submitted:
            st_result_text, results = scan_prompt(
                    vault, enabled_scanners, settings, st_prompt_text, st_fail_fast)
            st_is_valid = all(item["is_valid"] for item in results)
            show_scanning_report(st_is_valid,st_result_text,results)


except Exception as e:
    logger.error(e)
    traceback.print_exc()
    st.error(e)



