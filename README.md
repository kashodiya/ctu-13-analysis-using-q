# CTU-13 Dataset Explorer

Interactive web application for exploring and analyzing the CTU-13 botnet dataset.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Download CTU-13 data:**
   ```bash
   wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow
   ```

3. **Run the app:**
   ```bash
   streamlit run ctu13_explorer.py
   ```

4. **Load the dataset:**
   - The file path `capture20110810.binetflow` is pre-filled
   - Click "Load Dataset" button
   - Explore the data in different tabs

## Features

- **Data Loader:** Load CTU-13 binetflow files directly from disk
- **Traffic Analysis:** Visualize protocol distribution, bytes, packets, and top talkers
- **Botnet Detection:** Compare botnet vs normal traffic characteristics
- **Insights:** Learn key patterns and detection strategies

## Dataset Information

CTU-13 contains labeled botnet traffic from 13 scenarios including:
- **Scenario 1 (Neris):** IRC-based botnet with C&C communication
- Rbot, Virut, Menti, Sogou, Murlo, and NSIS.ay botnets in other scenarios
- Captured at Czech Technical University
- Binetflow format (bidirectional NetFlow)

## Dataset Details

- **Total Flows:** 2.8+ million network flows
- **Size:** 369 MB
- **Date:** August 10, 2011
- **Botnet Type:** Neris (IRC botnet)
- **Labels:** Both malicious and background/normal traffic

## Usage Tips

- The app loads data directly from disk (no 200MB upload limit)
- Use filters to focus on specific traffic types
- Compare metrics between botnet and normal traffic
- Explore temporal patterns and connection characteristics
- Export insights for further analysis

## Alternative Scenarios

Download other scenarios from:
https://www.stratosphereips.org/datasets-ctu13

## Technologies Used

- Python 3
- Streamlit (Interactive web framework)
- Pandas (Data analysis)
- Plotly (Visualizations)
