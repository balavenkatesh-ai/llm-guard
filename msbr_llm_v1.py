import streamlit as st
import time
import os
from langchain.llms import LlamaCpp
from langchain import PromptTemplate, LLMChain
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from huggingface_hub import hf_hub_download
import pandas as pd


def llama_model_path():
    model_name_or_path = "TheBloke/Llama-2-13B-chat-GGML"
    model_basename = "llama-2-13b-chat.ggmlv3.q5_1.bin"

    if os.path.exists(model_basename):
        st.write("Using locally available model...")
        model_path = model_basename
    else:
        st.write("Downloading model...")
        model_path = hf_hub_download(repo_id=model_name_or_path, filename=model_basename)
        
    return model_path


def run_llama_model(template):
    response_placeholder = st.empty()

    # template = """SYSTEM: As a cyber security expert, your task is to prepare a list of 20 threats.
    # USER: Please provide Threat Names, Attack Domains, Threat Descriptions, Countermeasures, CAPEC Reference URLs, and References for the {component_name} component, version {component_version}.

    # To structure your data, follow these guidelines:

    # 1. Threat Name: A descriptive name for each potential threat (e.g., Data Manipulation).
    # 2. Attack Domain: Specify the category of attack, such as network or application.
    # 3. Threat Description: Offer a concise explanation of the potential attack. For example, describe how attackers can manipulate data in MongoDB due to improper access controls or vulnerabilities in the application using the database.
    # 4. Countermeasure: Suggest recommendations to mitigate each threat.
    # 5. CAPEC Reference URL: Include the URL of the CAPEC (Common Attack Pattern Enumeration and Classification) database for each threat, linking to its CAPEC page.
    # 6. References: Provide reference source names or URLs to verify the accuracy of the threat information provided.

    # Output: Format the data in Markdown with appropriate headings and tables.

    # ASSISTANT: 
    # """
                
    prompt = PromptTemplate(template=template)

    callback_manager = CallbackManager([StreamingStdOutCallbackHandler()])

    n_gpu_layers = 40
    n_batch = 512

    llm = LlamaCpp(
        model_path=llama_model_path(),
        max_tokens=2024,
        n_gpu_layers=n_gpu_layers,
        n_batch=n_batch,
        callback_manager=callback_manager,
        verbose=True,
        n_ctx=4096,
        stop=['USER:'],
        temperature=0.2,
    )

    llm_chain = LLMChain(prompt=prompt, llm=llm)

    chain_input = {}

    response = llm_chain.run(chain_input)
    st.write("Generated MSBR LLM Threat Report:")

    st.markdown(response)
    #st.write(response)