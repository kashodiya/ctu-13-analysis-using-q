import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import numpy as np

st.set_page_config(page_title="CTU-13 Dataset Explorer", layout="wide")

st.title("🔒 CTU-13 Botnet Dataset Explorer")
st.markdown("Interactive analysis tool for CTU-13 cybersecurity dataset")

@st.cache_data
def load_data(file_path):
    df = pd.read_csv(file_path)
    return df

def parse_binetflow(file_path):
    cols = ['StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir', 'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts', 'TotBytes', 'SrcBytes', 'Label']
    df = pd.read_csv(file_path, skiprows=1, names=cols)
    df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce')
    return df

tab1, tab2, tab3, tab4 = st.tabs(["📁 Data Loader", "📊 Traffic Analysis", "🤖 Botnet Detection", "💡 Insights"])

with tab1:
    st.header("Load CTU-13 Dataset")
    st.markdown("""
    **About CTU-13:** Captured botnet traffic from 13 different scenarios at CTU University.
    Each scenario contains normal and botnet traffic (Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay).
    """)
    
    file_path = st.text_input("Enter path to binetflow file:", value="capture20110810.binetflow")
    
    if st.button("Load Dataset") or 'df' in st.session_state:
        if 'df' not in st.session_state and file_path:
            try:
                df = parse_binetflow(file_path)
                st.session_state['df'] = df
                st.success(f"Loaded {len(df):,} flows")
            except Exception as e:
                st.error(f"Error loading file: {e}")
                st.stop()
        
        if 'df' in st.session_state:
            df = st.session_state['df']
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Flows", f"{len(df):,}")
            col2.metric("Unique IPs", f"{df['SrcAddr'].nunique() + df['DstAddr'].nunique():,}")
            col3.metric("Protocols", df['Proto'].nunique())
            col4.metric("Malicious Flows", f"{df[df['Label'].str.contains('Botnet', na=False)].shape[0]:,}")
            
            st.subheader("Sample Data")
            st.dataframe(df.head(100), use_container_width=True)

with tab2:
    if 'df' in st.session_state:
        df = st.session_state['df']
        st.header("Traffic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Protocol Distribution")
            proto_counts = df['Proto'].value_counts()
            fig = px.pie(values=proto_counts.values, names=proto_counts.index, title="Protocols")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Traffic by Label")
            label_counts = df['Label'].value_counts().head(10)
            fig = px.bar(x=label_counts.index, y=label_counts.values, title="Top Labels")
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Bytes Distribution")
        col1, col2 = st.columns(2)
        with col1:
            fig = px.histogram(df[df['TotBytes'] < df['TotBytes'].quantile(0.95)], x='TotBytes', nbins=50, title="Total Bytes (95th percentile)")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.histogram(df[df['TotPkts'] < df['TotPkts'].quantile(0.95)], x='TotPkts', nbins=50, title="Total Packets (95th percentile)")
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Top Talkers")
        col1, col2 = st.columns(2)
        with col1:
            top_src = df['SrcAddr'].value_counts().head(10)
            st.write("**Top Source IPs**")
            st.dataframe(top_src, use_container_width=True)
        with col2:
            top_dst = df['DstAddr'].value_counts().head(10)
            st.write("**Top Destination IPs**")
            st.dataframe(top_dst, use_container_width=True)
    else:
        st.info("Load data in the Data Loader tab first")

with tab3:
    if 'df' in st.session_state:
        df = st.session_state['df']
        st.header("Botnet Detection Analysis")
        
        df['IsBotnet'] = df['Label'].str.contains('Botnet', na=False)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Botnet Flows", f"{df['IsBotnet'].sum():,}")
        col2.metric("Normal Flows", f"{(~df['IsBotnet']).sum():,}")
        col3.metric("Botnet %", f"{df['IsBotnet'].mean()*100:.2f}%")
        
        st.subheader("Botnet vs Normal Traffic Characteristics")
        
        col1, col2 = st.columns(2)
        with col1:
            comparison = df.groupby('IsBotnet')[['TotBytes', 'TotPkts', 'Dur']].mean()
            comparison.index = ['Normal', 'Botnet']
            st.write("**Average Metrics**")
            st.dataframe(comparison, use_container_width=True)
        
        with col2:
            proto_by_type = pd.crosstab(df['Proto'], df['IsBotnet'], normalize='columns') * 100
            proto_by_type.columns = ['Normal', 'Botnet']
            st.write("**Protocol Distribution (%)**")
            st.dataframe(proto_by_type.head(10), use_container_width=True)
        
        st.subheader("Botnet IP Addresses")
        botnet_ips = df[df['IsBotnet']][['SrcAddr', 'DstAddr', 'Label']].drop_duplicates()
        st.dataframe(botnet_ips.head(50), use_container_width=True)
        
        st.subheader("Connection States")
        state_counts = df.groupby(['State', 'IsBotnet']).size().unstack(fill_value=0)
        state_counts.columns = ['Normal', 'Botnet']
        fig = px.bar(state_counts, barmode='group', title="Connection States by Traffic Type")
        st.plotly_chart(fig, use_container_width=True)
        
    else:
        st.info("Load data in the Data Loader tab first")

with tab4:
    if 'df' in st.session_state:
        df = st.session_state['df']
        st.header("Key Insights & Learning")
        
        st.subheader("🎯 Dataset Summary")
        st.write(f"""
        - **Total Network Flows:** {len(df):,}
        - **Time Range:** {df['StartTime'].min()} to {df['StartTime'].max()}
        - **Unique Source IPs:** {df['SrcAddr'].nunique():,}
        - **Unique Destination IPs:** {df['DstAddr'].nunique():,}
        - **Botnet Traffic:** {df['IsBotnet'].sum():,} flows ({df['IsBotnet'].mean()*100:.2f}%)
        """)
        
        st.subheader("🔍 Behavioral Patterns")
        
        botnet_df = df[df['IsBotnet']]
        normal_df = df[~df['IsBotnet']]
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Botnet Characteristics:**")
            st.write(f"- Avg bytes/flow: {botnet_df['TotBytes'].mean():.0f}")
            st.write(f"- Avg packets/flow: {botnet_df['TotPkts'].mean():.0f}")
            st.write(f"- Avg duration: {botnet_df['Dur'].mean():.2f}s")
            st.write(f"- Most common protocol: {botnet_df['Proto'].mode()[0] if len(botnet_df) > 0 else 'N/A'}")
        
        with col2:
            st.write("**Normal Traffic Characteristics:**")
            st.write(f"- Avg bytes/flow: {normal_df['TotBytes'].mean():.0f}")
            st.write(f"- Avg packets/flow: {normal_df['TotPkts'].mean():.0f}")
            st.write(f"- Avg duration: {normal_df['Dur'].mean():.2f}s")
            st.write(f"- Most common protocol: {normal_df['Proto'].mode()[0] if len(normal_df) > 0 else 'N/A'}")
        
        st.subheader("📚 Learning Points")
        st.markdown("""
        **Key Observations from CTU-13:**
        1. **Protocol Patterns:** Botnets often use specific protocols (IRC, HTTP) for C&C communication
        2. **Traffic Volume:** Botnet traffic may show different byte/packet ratios than normal traffic
        3. **Connection Duration:** Persistent connections can indicate C&C channels
        4. **Port Usage:** Unusual port combinations may signal malicious activity
        5. **IP Reputation:** Repeated connections to suspicious IPs are red flags
        
        **Detection Strategies:**
        - Monitor for unusual protocol distributions
        - Track connection state anomalies
        - Identify high-volume talkers
        - Analyze temporal patterns
        - Correlate multiple indicators
        """)
        
        st.subheader("🎓 Next Steps")
        st.markdown("""
        - **Feature Engineering:** Extract features like flow duration, packet rate, byte rate
        - **ML Models:** Train classifiers (Random Forest, XGBoost) for botnet detection
        - **Temporal Analysis:** Analyze traffic patterns over time
        - **Network Graph:** Build IP relationship graphs to identify botnet clusters
        - **Signature Development:** Create detection rules based on observed patterns
        """)
    else:
        st.info("Load data in the Data Loader tab first")

st.sidebar.header("About CTU-13")
st.sidebar.markdown("""
**CTU-13 Dataset** contains 13 scenarios of botnet traffic:
- Scenario 1: Neris botnet
- Scenario 2: Neris botnet  
- Scenario 3: Rbot botnet
- Scenario 4: Rbot botnet
- Scenario 5: Virut botnet
- Scenario 6: Menti botnet
- Scenario 7: Sogou botnet
- Scenario 8: Murlo botnet
- Scenario 9: Neris botnet
- Scenario 10: Rbot botnet
- Scenario 11: Rbot botnet
- Scenario 12: NSIS.ay botnet
- Scenario 13: Virut botnet

**Data Format:** Binetflow (bidirectional NetFlow)
""")
