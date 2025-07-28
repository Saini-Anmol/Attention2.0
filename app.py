%%writefile app.py
import streamlit as st
from backend import (
    handle_general_chat, 
    handle_nvd_query, 
    handle_exploit_query, 
    process_nessus_pdf_locally, 
    process_nessus_pdf_gemini, 
    configure_gemini, 
    create_project_pdf
)
from datetime import datetime

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Cyber Analyst Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR A HIGHLY ADVANCED, MODERN UI ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
    
    /* Main App Styling */
    html, body, [class*="st-"], [class*="css-"] {
        font-family: 'Roboto', sans-serif;
    }
    .stApp {
        background-color: #f0f4f8; /* A slightly cooler, more modern light grey */
    }

    /* Card-like containers with enhanced styling */
    .st-emotion-cache-z5fcl4, .st-emotion-cache-1r6slb0 {
        border-radius: 16px;
        padding: 2rem !important;
        background-color: #ffffff;
        box-shadow: 0 8px 32px rgba(0,0,0,0.07);
        border: 1px solid #e0e0e0;
        transition: all 0.3s ease-in-out;
    }
    .st-emotion-cache-z5fcl4:hover, .st-emotion-cache-1r6slb0:hover {
        box-shadow: 0 12px 40px rgba(0,0,0,0.1);
        transform: translateY(-4px);
    }

    /* Button Styling */
    .stButton>button {
        border-radius: 8px;
        border: none;
        background: linear-gradient(90deg, #4285F4, #357ae8);
        color: white;
        transition: all 0.3s ease-in-out;
        font-weight: 500;
        padding: 0.5rem 1rem;
    }
    .stButton>button:hover {
        box-shadow: 0 4px 15px rgba(66, 133, 244, 0.4);
        transform: translateY(-2px);
    }

    /* Special button for scanning */
    .stLinkButton>a {
        border-radius: 8px;
        font-weight: 700;
        background: linear-gradient(90deg, #34A853, #2c8f45);
        color: white;
        transition: all 0.3s ease-in-out;
        padding: 0.75rem 1rem;
    }
    .stLinkButton>a:hover {
        box-shadow: 0 4px 15px rgba(52, 168, 83, 0.4);
        transform: translateY(-2px);
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 16px;
        border-bottom: 2px solid #e0e0e0;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        background-color: transparent;
        border-radius: 8px 8px 0 0;
        font-weight: 500;
        border-bottom: 2px solid transparent;
        transition: all 0.2s ease-in-out;
    }
    .stTabs [aria-selected="true"] {
        border-bottom: 2px solid #4285F4;
        color: #4285F4;
    }

    /* Header Styling */
    h1 {
        color: #1a237e; /* Dark blue for high contrast */
        font-weight: 700;
    }
    h3 {
        color: #3c4043;
        font-weight: 500;
        border-bottom: 2px solid #f0f4f8;
        padding-bottom: 10px;
    }

    /* Sidebar Styling */
    .st-emotion-cache-16txtl3 {
        background-color: #ffffff;
        border-right: 1px solid #e0e0e0;
    }

</style>
""", unsafe_allow_html=True)


# --- SESSION STATE INITIALIZATION ---
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "general_messages" not in st.session_state: st.session_state.general_messages = []
if "nvd_messages" not in st.session_state: st.session_state.nvd_messages = []
if "exploit_messages" not in st.session_state: st.session_state.exploit_messages = []
if "nessus_summary" not in st.session_state: st.session_state.nessus_summary = ""

# --- HEADER ---
header_cols = st.columns([0.7, 0.3])
with header_cols[0]:
    st.title("Cyber Analyst Pro 2.0")
    st.markdown(
        "<h4 style='color: #5f6368; font-weight: 400;'>Developed by <strong>Anmol Saini</strong></h4>",
        unsafe_allow_html=True
    )
with header_cols[1]:
    st.link_button("🚀 Start New Scan", "https://www.google.com", use_container_width=True)

st.markdown("---")

# --- MAIN LAYOUT ---
main_cols = st.columns([2, 1.5])

# --- LEFT COLUMN: CHAT INTERFACE ---
with main_cols[0]:
    st.header("Chat Interface")
    
    tab1, tab2, tab3 = st.tabs(["🤖 General AI Chat", "🛡️ NVD Vulnerability Search", "💥 Exploit-DB Search"])

    with tab1:
        for msg in st.session_state.general_messages:
            with st.chat_message(msg["role"], avatar="👤" if msg["role"] == "user" else "🤖"): st.markdown(msg["content"])
        if prompt := st.chat_input("Ask a general question..."):
            if st.session_state.api_key:
                st.session_state.general_messages.append({"role": "user", "content": prompt})
                with st.chat_message("user", avatar="👤"): st.markdown(prompt)
                with st.spinner("Thinking..."):
                    response = handle_general_chat(prompt, st.session_state.api_key)
                    st.session_state.general_messages.append({"role": "assistant", "content": response})
                st.rerun()
            else:
                st.warning("Please enter your API key in the sidebar to use this feature.")

    with tab2:
        st.info("Ask for specific details about a CVE. Ex: `CVSS score for CVE-2021-44228`")
        for msg in st.session_state.nvd_messages:
            with st.chat_message(msg["role"], avatar="👤" if msg["role"] == "user" else "🛡️"): st.markdown(msg["content"])
        if prompt := st.chat_input("Search NVD..."):
            if st.session_state.api_key:
                st.session_state.nvd_messages.append({"role": "user", "content": prompt})
                with st.chat_message("user", avatar="👤"): st.markdown(prompt)
                with st.spinner("Searching NVD..."):
                    response = handle_nvd_query(prompt, st.session_state.api_key)
                    st.session_state.nvd_messages.append({"role": "assistant", "content": response})
                st.rerun()
            else:
                st.warning("Please enter your API key in the sidebar to use this feature.")

    with tab3:
        st.info("Provide a CVE ID to find related exploit information. Ex: `CVE-2016-5195`")
        for msg in st.session_state.exploit_messages:
            with st.chat_message(msg["role"], avatar="👤" if msg["role"] == "user" else "💥"): st.markdown(msg["content"])
        if prompt := st.chat_input("Search Exploit-DB..."):
            st.session_state.exploit_messages.append({"role": "user", "content": prompt})
            with st.chat_message("user", avatar="👤"): st.markdown(prompt)
            with st.spinner("Searching Exploit-DB..."):
                response = handle_exploit_query(prompt, st.session_state.api_key)
                st.session_state.exploit_messages.append({"role": "assistant", "content": response})
            st.rerun()

# --- RIGHT COLUMN: TOOLS & ACTIONS ---
with main_cols[1]:
    with st.container():
        st.header("Nessus Report Summarizer")
        uploaded_file = st.file_uploader("Upload your Nessus report (PDF)", type="pdf")
        
        button_cols = st.columns(2)
        with button_cols[0]:
            if st.button("📊 Generate Summary (Local)", use_container_width=True):
                if uploaded_file:
                    with st.spinner("Processing report locally..."):
                        pdf_bytes = uploaded_file.getvalue()
                        summary = process_nessus_pdf_locally(pdf_bytes)
                        st.session_state.nessus_summary = summary
                        st.rerun()
                else:
                    st.warning("Please upload a PDF file first.")
        
        with button_cols[1]:
            if st.button("✨ Generate Summary (AI)", use_container_width=True):
                if uploaded_file and st.session_state.api_key:
                    with st.spinner("Processing with Gemini AI..."):
                        pdf_bytes = uploaded_file.getvalue()
                        summary = process_nessus_pdf_gemini(pdf_bytes, st.session_state.api_key)
                        st.session_state.nessus_summary = summary
                        st.rerun()
                elif not st.session_state.api_key:
                    st.warning("Please enter your API key in the sidebar.")
                else:
                    st.warning("Please upload a PDF file first.")

    if st.session_state.nessus_summary:
        st.markdown("---")
        with st.container():
            st.write("### 📄 Report Summary")
            st.markdown(st.session_state.nessus_summary)
            if st.button("Clear Summary"):
                st.session_state.nessus_summary = ""
                st.rerun()

# --- SIDEBAR ---
with st.sidebar:
    st.header("🛠️ Configuration & Actions")
    
    # --- **UPDATED** API Key Handling ---
    # This re-introduces the manual text input for the API key.
    api_key_input = st.text_input(
        "Your Security Token",
        type="password",
        key="api_key_sidebar",
        help="Your Gemini API key is required for the AI Chat and NVD Search features."
    )
    if api_key_input:
        st.session_state.api_key = api_key_input
        if configure_gemini(st.session_state.api_key):
            st.success("Key configured!")
        else:
            st.error("Invalid Key.")

    st.markdown("---")
    
    if st.button("🗑️ Clear All Chat History", use_container_width=True):
        st.session_state.general_messages = []
        st.session_state.nvd_messages = []
        st.session_state.exploit_messages = []
        st.rerun()

    all_messages = st.session_state.general_messages + st.session_state.nvd_messages + st.session_state.exploit_messages
    if all_messages:
        pdf_bytes = create_project_pdf(all_messages)
        st.download_button(
            label="💾 Download Project Archive (PDF)",
            data=pdf_bytes,
            file_name=f"Cyber_Analyst_Archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            use_container_width=True
        )
