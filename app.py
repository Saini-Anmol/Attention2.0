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

# --- CUSTOM CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
    /* ... (Your custom CSS is preserved here) ... */
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
    # ... (Tab logic is preserved) ...

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
    try:
        # This will automatically use the secret key when deployed
        st.session_state.api_key = st.secrets["GEMINI_API_KEY"]
        if configure_gemini(st.session_state.api_key):
            st.success("API Key configured from secrets.")
    except (KeyError, FileNotFoundError):
        st.warning("API Key not found in secrets. Please add it in your Streamlit Cloud settings for AI features to work.")
        st.info("You can still use the Local Nessus Parser and Exploit-DB Search.")

    st.markdown("---")
    if st.button("🗑️ Clear All Chat History", use_container_width=True):
        st.session_state.general_messages, st.session_state.nvd_messages, st.session_state.exploit_messages = [], [], []
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
