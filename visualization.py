import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import numpy as np
from typing import Dict, Optional, List, Tuple
import math

class NetworkVisualizer:
    """
    Advanced network visualization for cybersecurity simulation.
    Creates interactive, animated visualizations of attack propagation.
    """
    
    def __init__(self):
        self.color_scheme = {
            "safe": "#2ECC71",        # Green
            "compromised": "#E74C3C",  # Red
            "high_risk": "#F39C12",    # Orange
            "medium_risk": "#3498DB",  # Blue
            "low_risk": "#95A5A6",     # Gray
            "attack_path": "#8E44AD",  # Purple
            "background": "#1E1E1E",   # Dark background
            "text": "#FFFFFF"          # White text
        }
    
    def create_network_graph(self, network_config: Dict, simulation_results: Optional[Dict] = None) -> go.Figure:
        """Create interactive network visualization with attack propagation"""
        
        # Build NetworkX graph
        G = self._build_networkx_graph(network_config)
        
        # Generate layout
        pos = self._generate_layout(G)
        
        # Create node traces
        node_traces = self._create_node_traces(G, pos, simulation_results)
        
        # Create edge traces
        edge_traces = self._create_edge_traces(G, pos, simulation_results)
        
        # Combine all traces
        fig_data = edge_traces + node_traces
        
        # Create figure
        fig = go.Figure(data=fig_data)
        
        # Update layout
        fig.update_layout(
            title=dict(
                text="Smart Manufacturing Network - Cybersecurity Simulation",
                x=0.5,
                font=dict(size=20, color=self.color_scheme["text"])
            ),
            showlegend=True,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            annotations=[
                dict(
                    text="Nodes: Devices | Edges: Dependencies | Colors: Risk/Compromise Status",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(color=self.color_scheme["text"], size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor=self.color_scheme["background"],
            paper_bgcolor=self.color_scheme["background"],
            font=dict(color=self.color_scheme["text"])
        )
        
        return fig
    
    def _build_networkx_graph(self, network_config: Dict) -> nx.DiGraph:
        """Build NetworkX graph from configuration"""
        G = nx.DiGraph()
        
        # Add nodes
        for device_name, risk_score in network_config["devices"].items():
            G.add_node(device_name, risk_score=risk_score)
        
        # Add edges
        for dependency in network_config["dependencies"]:
            G.add_edge(
                dependency["from"], 
                dependency["to"], 
                weight=dependency.get("weight", 1.0)
            )
        
        return G
    
    def _generate_layout(self, G: nx.DiGraph) -> Dict:
        """Generate optimal layout for network visualization"""
        # Try hierarchical layout first for directed graphs
        try:
            pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
        except:
            # Fallback to spring layout
            pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Normalize positions to [0, 1] range
        if pos:
            x_values = [coord[0] for coord in pos.values()]
            y_values = [coord[1] for coord in pos.values()]
            
            x_min, x_max = min(x_values), max(x_values)
            y_min, y_max = min(y_values), max(y_values)
            
            # Avoid division by zero
            x_range = max(x_max - x_min, 1)
            y_range = max(y_max - y_min, 1)
            
            pos = {
                node: (
                    (coord[0] - x_min) / x_range,
                    (coord[1] - y_min) / y_range
                )
                for node, coord in pos.items()
            }
        
        return pos
    
    def _create_node_traces(self, G: nx.DiGraph, pos: Dict, simulation_results: Optional[Dict] = None) -> List[go.Scatter]:
        """Create node traces for visualization"""
        traces = []
        
        # Group nodes by status
        node_groups = self._group_nodes_by_status(G, simulation_results)
        
        for status, nodes in node_groups.items():
            if not nodes:
                continue
            
            x_coords = [pos[node][0] for node in nodes]
            y_coords = [pos[node][1] for node in nodes]
            
            # Create hover text
            hover_text = []
            for node in nodes:
                risk_score = G.nodes[node]["risk_score"]
                hover_info = f"<b>{node}</b><br>"
                hover_info += f"Risk Score: {risk_score:.2f}<br>"
                
                if simulation_results and node in simulation_results.get("device_states", {}):
                    device_state = simulation_results["device_states"][node]
                    if device_state["compromised"]:
                        hover_info += f"<span style='color:red'>COMPROMISED</span><br>"
                        hover_info += f"Compromise Time: {device_state['compromise_time']:.1f}s<br>"
                        hover_info += f"Attack Source: {device_state['attack_source']}"
                    else:
                        hover_info += f"<span style='color:#2ECC71'>SECURE</span><br>"
                    hover_text.append(hover_info)

            traces.append(go.Scatter(
                x=x_coords,
                y=y_coords,
                mode='markers+text',
                marker=dict(
                    size=18,
                    color=self._get_node_color(status),
                    line=dict(width=2, color='#FFFFFF')
                ),
                text=nodes,
                textposition='top center',
                hoverinfo='text',
                hovertext=hover_text,
                name=status.upper()
            ))
        
        return traces

    def _create_edge_traces(self, G: nx.DiGraph, pos: Dict, simulation_results: Optional[Dict]) -> List[go.Scatter]:
        """Create edge traces with optional highlighting for attack paths"""
        edge_x = []
        edge_y = []
        edge_colors = []

        compromised_edges = set()
        if simulation_results:
            for step in simulation_results.get("propagation_steps", []):
                compromised_edges.add((step["source"], step["target"]))

        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

            if edge in compromised_edges:
                edge_colors.append(self.color_scheme["attack_path"])
            else:
                edge_colors.append("#AAAAAA")

        trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=2, color="#AAAAAA"),
            hoverinfo='none',
            mode='lines',
            name="Network Links"
        )
        return [trace]

    def _get_node_color(self, status: str) -> str:
        """Return color based on node status"""
        mapping = {
            "compromised": self.color_scheme["compromised"],
            "high_risk": self.color_scheme["high_risk"],
            "medium_risk": self.color_scheme["medium_risk"],
            "low_risk": self.color_scheme["low_risk"],
            "safe": self.color_scheme["safe"]
        }
        return mapping.get(status, "#888888")

    def _group_nodes_by_status(self, G: nx.DiGraph, simulation_results: Optional[Dict]) -> Dict[str, List[str]]:
        """Group nodes into compromised, high/med/low risk, or safe"""
        groups = {
            "compromised": [],
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "safe": []
        }

        for node in G.nodes():
            risk_score = G.nodes[node]["risk_score"]
            if simulation_results and node in simulation_results.get("device_states", {}):
                if simulation_results["device_states"][node]["compromised"]:
                    groups["compromised"].append(node)
                    continue

            if risk_score > 0.7:
                groups["high_risk"].append(node)
            elif risk_score > 0.4:
                groups["medium_risk"].append(node)
            elif risk_score > 0.1:
                groups["low_risk"].append(node)
            else:
                groups["safe"].append(node)

        return groups
