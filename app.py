import streamlit as st
import json
import pandas as pd
from pathlib import Path
import time
from datetime import datetime

# Import custom modules
from simulation_engine import CyberAttackSimulator
from visualization import NetworkVisualizer
from util import load_json_file, save_simulation_report, format_log_entry

# Page configuration
st.set_page_config(
    page_title="CyberSec Manufacturing Simulator",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
def load_css():
    css_path = Path("assets/custom.css")
    if css_path.exists():
        with open(css_path) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# Initialize session state
if 'simulation_results' not in st.session_state:
    st.session_state.simulation_results = None
if 'network_data' not in st.session_state:
    st.session_state.network_data = {
        "devices": {},
        "dependencies": []
    }
if 'attack_scenario' not in st.session_state:
    st.session_state.attack_scenario = None
if 'simulation_log' not in st.session_state:
    st.session_state.simulation_log = []

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🏭 Cybersecurity in Smart Manufacturing</h1>
        <h3>Risk Assessment, Challenges, and Strategic Countermeasures</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for configuration
    with st.sidebar:
        st.markdown("### 🔧 Configuration Panel")
        
        # Network Configuration Section
        st.markdown("#### 📡 Network Configuration")
        config_option = st.radio(
            "Choose configuration method:",
            ["Upload JSON file", "Use sample data", "Manual input"]
        )
        
        if config_option == "Upload JSON file":
            uploaded_file = st.file_uploader(
                "Upload factory configuration (JSON)",
                type=['json'],
                help="Upload a JSON file with devices and dependencies"
            )
            if uploaded_file:
                try:
                    loaded_data = json.load(uploaded_file)
                    if "devices" in loaded_data and "dependencies" in loaded_data:
                        st.session_state.network_data = loaded_data
                        st.success("✅ Configuration loaded successfully!")
                    else:
                        st.error("❌ Invalid format: Must contain 'devices' and 'dependencies'")
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON format")
                except Exception as e:
                    st.error(f"❌ Error loading file: {str(e)}")
        
        elif config_option == "Use sample data":
            sample_data = {
                "devices": {
                    "IoT Sensor 1": 0.3,
                    "IoT Sensor 2": 0.4,
                    "Edge Gateway": 0.5,
                    "SCADA Server": 0.7,
                    "PLC Controller": 0.6,
                    "Industrial Robot": 0.8,
                    "Quality Control": 0.4,
                    "Manufacturing Database": 0.9
                },
                "dependencies": [
                    {"from": "IoT Sensor 1", "to": "Edge Gateway", "weight": 1.0},
                    {"from": "IoT Sensor 2", "to": "Edge Gateway", "weight": 1.0},
                    {"from": "Edge Gateway", "to": "SCADA Server", "weight": 1.5},
                    {"from": "SCADA Server", "to": "PLC Controller", "weight": 2.0},
                    {"from": "PLC Controller", "to": "Industrial Robot", "weight": 1.8},
                    {"from": "Industrial Robot", "to": "Quality Control", "weight": 1.2},
                    {"from": "SCADA Server", "to": "Manufacturing Database", "weight": 2.5}
                ]
            }
            st.session_state.network_data = sample_data
            st.success("✅ Sample data loaded!")
        
        elif config_option == "Manual input":
            st.markdown("**Add Devices:**")
            device_name = st.text_input("Device name")
            risk_score = st.slider("Risk score", 0.0, 1.0, 0.5, 0.1)
            
            if st.button("Add Device") and device_name:
                if st.session_state.network_data is None:
                    st.session_state.network_data = {"devices": {}, "dependencies": []}
                st.session_state.network_data["devices"][device_name] = risk_score
                st.rerun()
        
        st.markdown("---")
        
        with st.expander("🔍 Network Data Debug", expanded=False):  # expanded=False makes it collapsed by default
            st.write("Current network data:", st.session_state.get('network_data', {}).get("devices", "No devices loaded"))
            st.write("Full network state:", st.session_state.get('network_data', "No network data loaded"))

        # Attack Scenario Section
        st.markdown("#### ⚠️ Attack Scenario")

        # Ensure network data is loaded
        if not st.session_state.get('network_data') or not st.session_state.network_data.get("devices"):
            st.error("❌ No network devices loaded - please configure network first")
            st.markdown("---")
            return

        available_devices = list(st.session_state.network_data["devices"].keys())

        # Input method selection
        attack_input_method = st.radio(
            "Configure attack via:",
            ["Automatic selection", "Manual selection", "File upload"],
            horizontal=True,
            key="attack_method_selector"
        )

        # ------------------------
        # 1. ✅ Automatic selection
        # ------------------------
        if attack_input_method == "Automatic selection":
            st.markdown("Automatically select the top risky devices.")

            top_n = st.slider("Number of entry points", 1, len(available_devices), 2)
            
            sorted_devices = sorted(
                available_devices,
                key=lambda d: st.session_state.network_data["devices"][d],
                reverse=True
            )
            attack_entry_points = sorted_devices[:top_n]
            avg_risk = sum(st.session_state.network_data["devices"][d] for d in attack_entry_points) / len(attack_entry_points)

            st.info(f"Selected: {', '.join(attack_entry_points)}")
            st.metric("Average Risk Score", f"{avg_risk:.2f}")

            attack_description = st.text_area(
                "Attack description:",
                placeholder="Describe the attack...",
                key="auto_attack_desc"
            )

            if st.button("Set Attack Scenario", key="set_auto_attack"):
                st.session_state.attack_scenario = {
                    "attack_entry": attack_entry_points,
                    "description": attack_description or f"Automatically selected top {top_n} risky devices"
                }
                st.success("✅ Attack scenario configured automatically!")
                with st.expander("Current Attack Scenario"):
                    st.json(st.session_state.attack_scenario)
                    st.download_button(
                        label="💾 Save Current Scenario",
                        data=json.dumps(st.session_state.attack_scenario, indent=2),
                        file_name=f"attack_{datetime.now().strftime('%Y%m%d')}.json",
                        mime="application/json"
                    )

        # ------------------------
        # 2. ✍️ Manual selection
        # ------------------------
        elif attack_input_method == "Manual selection":
            st.markdown(f"Available devices ({len(available_devices)}):")
            st.code(", ".join(available_devices))
            
            col1, col2 = st.columns(2)
            with col1:
                attack_entry_points = st.multiselect(
                    "Select attack entry points:",
                    available_devices,
                    help="Choose which devices will be initially compromised",
                    key="attack_points"
                )
            with col2:
                if attack_entry_points:
                    risk_scores = [st.session_state.network_data["devices"][d] for d in attack_entry_points]
                    st.metric("Average Risk Score", f"{sum(risk_scores)/len(risk_scores):.2f}")
            
            attack_description = st.text_area(
                "Attack description:",
                placeholder="Describe the attack...",
                key="manual_attack_desc"
            )

            if st.button("Set Attack Scenario", key="set_manual_attack"):
                if attack_entry_points:
                    st.session_state.attack_scenario = {
                        "attack_entry": attack_entry_points,
                        "description": attack_description or "Manual attack scenario"
                    }
                    st.success("✅ Manual attack scenario set!")
                    with st.expander("Current Attack Scenario"):
                        st.json(st.session_state.attack_scenario)
                        st.download_button(
                            label="💾 Save Current Scenario",
                            data=json.dumps(st.session_state.attack_scenario, indent=2),
                            file_name=f"attack_{datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json"
                        )
                else:
                    st.error("Please select at least one attack entry point.")

        # ------------------------
        # 3. 📁 File upload
        # ------------------------
        elif attack_input_method == "File upload":
            uploaded_attack = st.file_uploader(
                "Upload attack scenario (JSON)",
                type=['json'],
                help="Must contain 'attack_entry' list and optional 'description'"
            )

            if uploaded_attack:
                try:
                    attack_data = json.load(uploaded_attack)
                    if "attack_entry" not in attack_data or not isinstance(attack_data["attack_entry"], list):
                        st.error("❌ Invalid format: Missing or malformed 'attack_entry'")
                    else:
                        invalid_devices = [
                            dev for dev in attack_data["attack_entry"]
                            if dev not in available_devices
                        ]
                        if invalid_devices:
                            st.error(f"❌ Devices not in network: {', '.join(invalid_devices)}")
                        elif not attack_data["attack_entry"]:
                            st.error("❌ Attack entry points cannot be empty")
                        else:
                            st.session_state.attack_scenario = {
                                "attack_entry": attack_data["attack_entry"],
                                "description": attack_data.get("description", "Uploaded attack scenario")
                            }
                            st.success("✅ Uploaded attack scenario configured!")
                            st.json(st.session_state.attack_scenario)
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON file - please check the format")

        st.markdown("---")

        
        # Simulation Controls
        st.markdown("#### 🎮 Simulation Controls")
        simulation_speed = st.slider("Simulation speed", 0.1, 2.0, 1.0, 0.1)
        show_real_time = st.checkbox("Real-time visualization", value=True)
        
        # Run Simulation Button
        if st.button("🚀 Run Simulation", type="primary"):
            if st.session_state.network_data and st.session_state.attack_scenario:
                run_simulation(simulation_speed, show_real_time)
            else:
                st.error("❌ Please configure network and attack scenario first!")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📊 Network Visualization")
        

        if (st.session_state.network_data and 
            isinstance(st.session_state.network_data, dict) and 
            "devices" in st.session_state.network_data):
            devices_df = pd.DataFrame([
                {"Device": name, "Risk Score": score} 
                for name, score in st.session_state.network_data["devices"].items()
            ])
        else:
            devices_df = pd.DataFrame(columns=["Device", "Risk Score"])
            st.warning("⚠️ No devices found in network configuration")
        
        # Visualization container
        viz_container = st.empty()
        
        if st.session_state.network_data:
            visualizer = NetworkVisualizer()
            fig = visualizer.create_network_graph(
                st.session_state.network_data,
                st.session_state.simulation_results
            )
            viz_container.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 📈 Simulation Results")
        
        if st.session_state.simulation_results:
            # Risk metrics
            results = st.session_state.simulation_results
            
            st.metric(
                "Overall Risk Score",
                f"{results['overall_risk_score']:.2f}",
                delta=f"{results['risk_increase']:.2f}"
            )
            
            st.metric(
                "Affected Devices",
                f"{results['affected_devices']}/{results['total_devices']}",
                delta=f"{results['propagation_rate']:.1%}"
            )
            
            st.metric(
                "Attack Duration",
                f"{results['attack_duration']:.1f}s"
            )
            
            # Attack path
            with st.expander("🔍 Attack Propagation Path"):
                for step, path_info in enumerate(results['attack_path']):
                    st.write(f"**Step {step + 1}:** {path_info['device']}")
                    st.write(f"Risk: {path_info['risk']:.2f} | Time: {path_info['time']:.1f}s")
            
            # Export results
            if st.button("📄 Export Report"):
                report_path = save_simulation_report(st.session_state.simulation_results)
                st.success(f"Report saved to: {report_path}")
        
        # Simulation log
        try:
            if st.session_state.simulation_log:
                log_text = "\n".join(st.session_state.simulation_log[-10:])
                st.text_area(
                    "simulation_log",
                    value=log_text,
                    height=200,
                    disabled=True,
                    label_visibility="collapsed"
                )
        except Exception as e:
            st.error(f"Error displaying logs: {str(e)}")

def run_simulation(speed, real_time):
    """Run the cyber attack simulation"""
    progress = st.progress(0)
    status = st.empty()
    
    try:
        # Initialize simulator
        simulator = CyberAttackSimulator(st.session_state.network_data)
        
        # Clear previous log
        st.session_state.simulation_log = []
        
        # Add initial log entry
        log_entry = format_log_entry("Simulation started", "INFO")
        st.session_state.simulation_log.append(log_entry)
        
        status.info("🔄 Initializing simulation...")
        progress.progress(10)
        time.sleep(0.5 / speed)
        
        # Run simulation
        status.info("🎯 Running attack simulation...")
        results = simulator.simulate_attack(
            st.session_state.attack_scenario,
            callback=lambda msg: st.session_state.simulation_log.append(
                format_log_entry(msg, "SIMULATION")
            )
        )
        
        progress.progress(70)
        time.sleep(0.5 / speed)
        
        # Store results
        st.session_state.simulation_results = results
        
        status.info("📊 Generating visualization...")
        progress.progress(90)
        time.sleep(0.3 / speed)
        
        # Final log entry
        log_entry = format_log_entry("Simulation completed successfully", "SUCCESS")
        st.session_state.simulation_log.append(log_entry)
        
        progress.progress(100)
        status.success("✅ Simulation completed successfully!")
        
        # Auto-refresh to show results
        time.sleep(1)
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Simulation failed: {str(e)}")
        log_entry = format_log_entry(f"Simulation failed: {str(e)}", "ERROR")
        st.session_state.simulation_log.append(log_entry)

if __name__ == "__main__":
    main()