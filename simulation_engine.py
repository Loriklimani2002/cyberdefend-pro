import networkx as nx
import numpy as np
import time
from collections import deque, defaultdict
from typing import Dict, List, Tuple, Optional, Callable
import random

class CyberAttackSimulator:
    """
    Advanced cyber attack simulation engine for smart manufacturing networks.
    Uses graph theory and probabilistic models to simulate attack propagation.
    """
    
    def __init__(self, network_config: Dict):
        """Initialize the simulation engine with network configuration"""
        self.network_config = network_config
        self.graph = self._build_network_graph()
        self.device_states = self._initialize_device_states()
        self.attack_timeline = []
        
    def _build_network_graph(self) -> nx.DiGraph:
        """Build directed graph from network configuration"""
        G = nx.DiGraph()
        
        # Add nodes (devices) with risk scores
        for device_name, risk_score in self.network_config["devices"].items():
            G.add_node(device_name, 
                      risk_score=risk_score,
                      compromised=False,
                      compromise_time=None,
                      attack_vector=None)
        
        # Add edges (dependencies) with weights
        for dependency in self.network_config["dependencies"]:
            G.add_edge(
                dependency["from"], 
                dependency["to"], 
                weight=dependency.get("weight", 1.0)
            )
        
        return G
    
    def _initialize_device_states(self) -> Dict:
        """Initialize device states for simulation"""
        states = {}
        for device in self.graph.nodes():
            states[device] = {
                "compromised": False,
                "compromise_probability": 0.0,
                "compromise_time": None,
                "attack_source": None,
                "security_level": 1.0 - self.graph.nodes[device]["risk_score"]
            }
        return states
    
    def simulate_attack(self, attack_scenario: Dict, callback: Optional[Callable] = None) -> Dict:
        """
        Main simulation function that runs the cyber attack propagation
        
        Args:
            attack_scenario: Dict containing attack entry points and description
            callback: Optional callback function for logging
            
        Returns:
            Dict containing simulation results and metrics
        """
        if callback:
            callback(f"Starting attack simulation: {attack_scenario['description']}")
        
        # Reset simulation state
        self._reset_simulation()
        
        # Initialize attack entry points
        entry_points = attack_scenario["attack_entry"]
        simulation_time = 0.0
        
        # Compromise initial entry points
        for entry_point in entry_points:
            self._compromise_device(entry_point, simulation_time, "Initial Attack")
            if callback:
                callback(f"Initial compromise: {entry_point}")
        
        # Propagation simulation using modified BFS with probabilistic elements
        attack_queue = deque([(device, simulation_time) for device in entry_points])
        propagation_steps = []
        
        while attack_queue:
            current_device, current_time = attack_queue.popleft()
            
            # Get neighboring devices (targets for lateral movement)
            neighbors = list(self.graph.successors(current_device))
            
            for neighbor in neighbors:
                if not self.device_states[neighbor]["compromised"]:
                    # Calculate attack success probability
                    success_prob = self._calculate_attack_probability(
                        current_device, neighbor, current_time
                    )
                    
                    # Simulate attack attempt
                    if random.random() < success_prob:
                        # Calculate propagation delay
                        edge_weight = self.graph.edges[current_device, neighbor]["weight"]
                        propagation_delay = self._calculate_propagation_delay(
                            current_device, neighbor, edge_weight
                        )
                        
                        new_time = current_time + propagation_delay
                        
                        # Compromise the target device
                        self._compromise_device(
                            neighbor, new_time, f"Lateral movement from {current_device}"
                        )
                        
                        # Add to propagation queue
                        attack_queue.append((neighbor, new_time))
                        
                        # Record propagation step
                        propagation_steps.append({
                            "source": current_device,
                            "target": neighbor,
                            "time": new_time,
                            "success_probability": success_prob,
                            "method": "Lateral Movement"
                        })
                        
                        if callback:
                            callback(f"Propagation: {current_device} → {neighbor} (t={new_time:.1f}s)")
        
        # Calculate simulation results
        results = self._calculate_results(attack_scenario, propagation_steps)
        
        if callback:
            callback(f"Simulation completed. {results['affected_devices']} devices compromised.")
        
        return results
    
    def _calculate_attack_probability(self, source: str, target: str, current_time: float) -> float:
        """Calculate probability of successful attack propagation"""
        base_prob = self.graph.nodes[target]["risk_score"]
        
        # Factor in edge weight (higher weight = easier propagation)
        edge_weight = self.graph.edges[source, target]["weight"]
        weight_factor = min(edge_weight / 2.0, 1.0)
        
        # Time decay factor (attacks become less effective over time)
        time_decay = max(0.1, 1.0 - (current_time / 100.0))
        
        # Network effect (more compromised neighbors increase probability)
        compromised_neighbors = sum(
            1 for pred in self.graph.predecessors(target)
            if self.device_states[pred]["compromised"]
        )
        network_effect = 1.0 + (compromised_neighbors * 0.2)
        
        final_probability = base_prob * weight_factor * time_decay * network_effect
        return min(final_probability, 0.95)  # Cap at 95%
    
    def _calculate_propagation_delay(self, source: str, target: str, edge_weight: float) -> float:
        """Calculate time delay for attack propagation"""
        # Base delay inversely related to edge weight
        base_delay = 5.0 / max(edge_weight, 0.1)
        
        # Add random variation (±30%)
        variation = random.uniform(-0.3, 0.3)
        delay = base_delay * (1 + variation)
        
        # Factor in target's security level
        security_factor = self.device_states[target]["security_level"]
        delay *= (1 + security_factor)
        
        return max(delay, 1.0)  # Minimum 1 second delay
    
    def _compromise_device(self, device: str, time: float, attack_vector: str):
        """Mark a device as compromised"""
        self.device_states[device]["compromised"] = True
        self.device_states[device]["compromise_time"] = time
        self.device_states[device]["attack_source"] = attack_vector
        
        # Update graph node
        self.graph.nodes[device]["compromised"] = True
        self.graph.nodes[device]["compromise_time"] = time
        self.graph.nodes[device]["attack_vector"] = attack_vector
        
        # Add to timeline
        self.attack_timeline.append({
            "device": device,
            "time": time,
            "risk": self.graph.nodes[device]["risk_score"],
            "attack_vector": attack_vector
        })
    
    def _reset_simulation(self):
        """Reset simulation state for new run"""
        self.device_states = self._initialize_device_states()
        self.attack_timeline = []
        
        # Reset graph node states
        for device in self.graph.nodes():
            self.graph.nodes[device]["compromised"] = False
            self.graph.nodes[device]["compromise_time"] = None
            self.graph.nodes[device]["attack_vector"] = None
    
    def _calculate_results(self, attack_scenario: Dict, propagation_steps: List) -> Dict:
        """Calculate comprehensive simulation results"""
        total_devices = len(self.graph.nodes())
        affected_devices = sum(1 for state in self.device_states.values() if state["compromised"])
        
        # Calculate overall risk score
        initial_risk = np.mean([
            self.graph.nodes[device]["risk_score"] 
            for device in self.graph.nodes()
        ])
        
        compromised_risk_scores = [
            self.graph.nodes[device]["risk_score"]
            for device in self.graph.nodes()
            if self.device_states[device]["compromised"]
        ]
        
        if compromised_risk_scores:
            post_attack_risk = np.mean(compromised_risk_scores) * (affected_devices / total_devices)
            risk_increase = post_attack_risk - initial_risk
        else:
            post_attack_risk = initial_risk
            risk_increase = 0.0
        
        # Calculate attack duration
        if self.attack_timeline:
            attack_duration = max(entry["time"] for entry in self.attack_timeline)
        else:
            attack_duration = 0.0
        
        # Sort attack timeline by time
        attack_path = sorted(self.attack_timeline, key=lambda x: x["time"])
        
        # Calculate additional metrics
        propagation_rate = affected_devices / total_devices if total_devices > 0 else 0
        
        # Critical devices compromised
        critical_devices = [
            device for device, state in self.device_states.items()
            if state["compromised"] and self.graph.nodes[device]["risk_score"] > 0.7
        ]
        
        # Network resilience score
        uncompromised_critical = [
            device for device in self.graph.nodes()
            if not self.device_states[device]["compromised"] 
            and self.graph.nodes[device]["risk_score"] > 0.7
        ]
        resilience_score = len(uncompromised_critical) / max(1, len([
            device for device in self.graph.nodes()
            if self.graph.nodes[device]["risk_score"] > 0.7
        ]))
        
        return {
            "attack_scenario": attack_scenario,
            "total_devices": total_devices,
            "affected_devices": affected_devices,
            "propagation_rate": propagation_rate,
            "overall_risk_score": post_attack_risk,
            "initial_risk_score": initial_risk,
            "risk_increase": risk_increase,
            "attack_duration": attack_duration,
            "attack_path": attack_path,
            "propagation_steps": propagation_steps,
            "critical_devices_compromised": critical_devices,
            "network_resilience_score": resilience_score,
            "compromise_timeline": self.attack_timeline,
            "device_states": self.device_states.copy(),
            "simulation_timestamp": time.time()
        }
    
    def get_network_metrics(self) -> Dict:
        """Calculate network topology metrics"""
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "average_clustering": nx.average_clustering(self.graph.to_undirected()),
            "is_connected": nx.is_weakly_connected(self.graph),
            "diameter": nx.diameter(self.graph) if nx.is_weakly_connected(self.graph) else "N/A",
            "average_shortest_path": nx.average_shortest_path_length(self.graph) if nx.is_weakly_connected(self.graph) else "N/A"
        }
    
    def get_vulnerability_analysis(self) -> Dict:
        """Analyze network vulnerabilities"""
        # Calculate centrality measures
        betweenness = nx.betweenness_centrality(self.graph)
        closeness = nx.closeness_centrality(self.graph)
        degree = nx.degree_centrality(self.graph)
        
        # Identify high-risk nodes
        high_risk_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data["risk_score"] > 0.6
        ]
        
        # Critical path analysis
        try:
            critical_paths = []
            for source in high_risk_nodes:
                for target in high_risk_nodes:
                    if source != target and nx.has_path(self.graph, source, target):
                        path = nx.shortest_path(self.graph, source, target)
                        if len(path) > 2:  # Non-trivial paths
                            critical_paths.append(path)
        except:
            critical_paths = []
        
        return {
            "high_risk_devices": high_risk_nodes,
            "centrality_analysis": {
                "betweenness": betweenness,
                "closeness": closeness,
                "degree": degree
            },
            "critical_paths": critical_paths[:5],  # Top 5 critical paths
            "most_vulnerable": max(self.graph.nodes(data=True), key=lambda x: x[1]["risk_score"])[0],
            "most_central": max(betweenness.items(), key=lambda x: x[1])[0]
        }