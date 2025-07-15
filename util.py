import json
import os
from datetime import datetime

def load_json_file(path: str) -> dict:
    """Load a JSON configuration file."""
    with open(path, 'r') as file:
        return json.load(file)

def save_simulation_report(results: dict, directory: str = "reports") -> str:
    """Save simulation results to a timestamped report file."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"simulation_report_{timestamp}.txt"
    filepath = os.path.join(directory, filename)
    
    with open(filepath, "w") as f:
        f.write("Cybersecurity Simulation Report\n")
        f.write("=" * 40 + "\n")
        f.write(f"Attack Description: {results['attack_scenario']['description']}\n\n")
        f.write(f"Total Devices: {results['total_devices']}\n")
        f.write(f"Affected Devices: {results['affected_devices']}\n")
        f.write(f"Propagation Rate: {results['propagation_rate']:.2f}\n")
        f.write(f"Risk Increase: {results['risk_increase']:.2f}\n")
        f.write(f"Attack Duration: {results['attack_duration']:.2f}s\n\n")

        f.write("Attack Timeline:\n")
        for step in results["attack_path"]:
            f.write(f"- {step['device']} | Risk: {step['risk']:.2f} | Time: {step['time']:.1f}s\n")

        f.write("\nCritical Devices Compromised:\n")
        for device in results["critical_devices_compromised"]:
            f.write(f"- {device}\n")

        f.write("\nResilience Score: {:.2f}\n".format(results["network_resilience_score"]))

    return filepath

def format_log_entry(message: str, level: str = "INFO") -> str:
    """Format log entries with timestamp and level."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    return f"[{timestamp}] [{level}] {message}"
