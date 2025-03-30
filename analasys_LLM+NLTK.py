import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from plotly.subplots import make_subplots
import base64
from io import BytesIO
import ipaddress
import asyncio
import aiofiles
import re
import logging
import sqlite3
from logging.handlers import RotatingFileHandler
import subprocess

# Set up SQLite database
def setup_database():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT,
            message TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Custom SQLite logging handler
class SQLiteHandler(logging.Handler):
    def __init__(self, db='logs.db'):
        logging.Handler.__init__(self)
        self.db = db

    def emit(self, record):
        log_entry = self.format(record)
        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (level, message) VALUES (?, ?)
        ''', (record.levelname, log_entry))
        conn.commit()
        conn.close()

# Set up logging
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Log to file with rotation
    file_handler = RotatingFileHandler('app.log', maxBytes=5*1024*1024*1024, backupCount=1)  # 5GB max size
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Log to SQLite database
    db_handler = SQLiteHandler()
    db_handler.setLevel(logging.DEBUG)
    db_formatter = logging.Formatter('%(message)s')
    db_handler.setFormatter(db_formatter)
    logger.addHandler(db_handler)

# Initialize database and logging
setup_database()
setup_logging()

# Example usage of logging
logging.info('Info message')
logging.warning('Warning message')
logging.error('Error message')

def run_comprehensive_scan(target):
    logging.info(f"Starting comprehensive scan for {target}")
    try:
        # Execute a comprehensive Nmap scan
        logging.warning("This scan will be extremely slow, especially through proxy chains.")
        nmap_command = f"nmap -A -p 1-65535 {target}"
        result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info(f"Comprehensive scan for {target} completed successfully")
            return result.stdout
        else:
            logging.error(f"Comprehensive scan for {target} failed: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error during comprehensive scan for {target}: {str(e)}")
        return None

class NetworkDataProcessor:
    """
    Processes network reconnaissance data for visualization and analysis
    """
    def __init__(self, results_dir: str = "recon_results"):
        self.results_dir = results_dir
        self.data = {}
        self.metrics = {}
        logging.info(f"NetworkDataProcessor initialized with results directory: {results_dir}")
        
    async def load_scan_results(self, target: str, scan_types: Optional[List[str]] = None) -> Dict:
        """Load scan results for the specified target"""
        logging.info(f"Loading scan results for target: {target} with scan types: {scan_types}")
        result_files = []
        
        # Find all result files for the target
        for filename in os.listdir(self.results_dir):
            if target in filename and filename.endswith('.json'):
                # Filter by scan type if specified
                if scan_types:
                    if any(scan_type in filename for scan_type in scan_types):
                        result_files.append(os.path.join(self.results_dir, filename))
                else:
                    result_files.append(os.path.join(self.results_dir, filename))
        
        # Process each result file
        for file_path in result_files:
            try:
                async with aiofiles.open(file_path, 'r') as f:
                    content = await f.read()
                    result_data = json.loads(content)
                    
                    # Extract scan type from filename
                    scan_type = os.path.basename(file_path).split('_')[0]
                    if scan_type not in self.data:
                        self.data[scan_type] = {}
                    
                    self.data[scan_type][target] = result_data
                    logging.info(f"Loaded scan results from {file_path}")
            except Exception as e:
                logging.error(f"Error loading {file_path}: {str(e)}")
        
        return self.data
    
    def extract_metrics(self) -> Dict:
        """Extract key metrics from loaded scan data"""
        logging.info("Extracting metrics from loaded scan data")
        self.metrics = {
            'ports': {},            # Open ports by target
            'services': {},         # Services by target
            'vulnerabilities': {},  # Vulnerabilities by target
            'response_times': {},   # Response times by target
            'subdomains': {},       # Subdomains by target
            'traceroute_hops': {},  # Traceroute hop counts by target
            'security_score': {}    # Calculated security score (lower is better)
        }
        
        # Process each scan type and target
        for scan_type, targets in self.data.items():
            for target, data in targets.items():
                # Initialize target metrics if not exist
                if target not in self.metrics['ports']:
                    self.metrics['ports'][target] = []
                if target not in self.metrics['services']:
                    self.metrics['services'][target] = []
                if target not in self.metrics['vulnerabilities']:
                    self.metrics['vulnerabilities'][target] = []
                if target not in self.metrics['response_times']:
                    self.metrics['response_times'][target] = None
                if target not in self.metrics['subdomains']:
                    self.metrics['subdomains'][target] = []
                if target not in self.metrics['traceroute_hops']:
                    self.metrics['traceroute_hops'][target] = 0
                
                # Process SMB info
                if 'smb_info' in data:
                    # Extract vulnerabilities
                    if 'vulnerabilities' in data['smb_info']:
                        self.metrics['vulnerabilities'][target].extend(data['smb_info']['vulnerabilities'])
                    
                    # Extract open ports from shares
                    if 'shares' in data['smb_info']:
                        self.metrics['ports'][target].append(445)  # SMB port
                
                # Process scan results
                if 'scan_results' in data:
                    for scanner, scan_result in data['scan_results'].items():
                        # Extract from Nmap scans
                        if 'nmap' in scanner.lower() and 'output' in scan_result:
                            self._extract_nmap_metrics(target, scan_result['output'])
                        
                        # Extract from ping
                        if scanner.lower() == 'ping' and 'output' in scan_result:
                            self._extract_ping_metrics(target, scan_result['output'])
                        
                        # Extract from traceroute
                        if scanner.lower() == 'traceroute' and 'output' in scan_result:
                            self._extract_traceroute_metrics(target, scan_result['output'])
                        
                        # Extract from sublist3r
                        if scanner.lower() == 'sublist3r' and 'output_file' in scan_result:
                            self._extract_subdomain_metrics(target, scan_result['output_file'])
        
        # Calculate security score
        self._calculate_security_scores()
        
        return self.metrics
    
    def _extract_nmap_metrics(self, target: str, output: str) -> None:
        """Extract metrics from Nmap output"""
        logging.info(f"Extracting Nmap metrics for target: {target}")
        if not output:
            return
            
        # Extract open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)?'
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            service = match.group(2) if match.group(2) else "unknown"
            
            if port not in self.metrics['ports'][target]:
                self.metrics['ports'][target].append(port)
            
            service_entry = {"port": port, "name": service}
            if service_entry not in self.metrics['services'][target]:
                self.metrics['services'][target].append(service_entry)
        
        # Extract vulnerabilities
        if "VULNERABLE" in output:
            for line in output.splitlines():
                if "VULNERABLE" in line:
                    vuln_name = line.strip()
                    if vuln_name not in self.metrics['vulnerabilities'][target]:
                        self.metrics['vulnerabilities'][target].append(vuln_name)
    
    def _extract_ping_metrics(self, target: str, output: str) -> None:
        """Extract metrics from ping output"""
        logging.info(f"Extracting ping metrics for target: {target}")
        if not output:
            return
            
        # Extract average response time
        avg_match = re.search(r'= [^/]*/([^/]*)/[^/]*/[^/]*\s', output)
        if avg_match:
            try:
                avg_time = float(avg_match.group(1))
                self.metrics['response_times'][target] = avg_time
            except (ValueError, TypeError):
                pass
    
    def _extract_traceroute_metrics(self, target: str, output: str) -> None:
        """Extract metrics from traceroute output"""
        logging.info(f"Extracting traceroute metrics for target: {target}")
        if not output:
            return
            
        # Count the number of hops
        hop_count = output.count('Hop #')
        if hop_count > 0:
            self.metrics['traceroute_hops'][target] = hop_count
    
    def _extract_subdomain_metrics(self, target: str, output_file: str) -> None:
        """Extract metrics from Sublist3r output file"""
        logging.info(f"Extracting subdomain metrics for target: {target} from file: {output_file}")
        if not output_file or not os.path.exists(output_file):
            return
            
        try:
            with open(output_file, 'r') as f:
                content = f.read()
                subdomains = [line.strip() for line in content.splitlines() if line.strip()]
                self.metrics['subdomains'][target].extend(subdomains)
        except Exception as e:
            logging.error(f"Error reading subdomains file: {str(e)}")
    
    def _calculate_security_scores(self) -> None:
        """Calculate security scores based on vulnerabilities and open ports"""
        logging.info("Calculating security scores")
        for target in self.metrics['ports'].keys():
            # Start with a baseline score
            score = 100
            
            # Subtract for each vulnerability (high impact)
            vuln_count = len(self.metrics['vulnerabilities'][target])
            score -= vuln_count * 15
            
            # Subtract for each open port (medium impact)
            port_count = len(self.metrics['ports'][target])
            score -= port_count * 5
            
            # Subtract for certain high-risk ports if open
            high_risk_ports = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
            for port in high_risk_ports:
                if port in self.metrics['ports'][target]:
                    score -= 3
            
            # Ensure score doesn't go below 0
            score = max(0, score)
            
            self.metrics['security_score'][target] = score
    
    def prepare_data_for_regression(self) -> Tuple[pd.DataFrame, List[str]]:
        """Prepare metrics data for regression analysis"""
        logging.info("Preparing data for regression analysis")
        # Create a list of dictionaries for each target
        data_list = []
        
        for target in self.metrics['ports'].keys():
            target_data = {
                'target': target,
                'ports_open': len(self.metrics['ports'][target]),
                'vulns_found': len(self.metrics['vulnerabilities'][target]),
                'response_time': self.metrics['response_times'][target] or 0,
                'traceroute_hops': self.metrics['traceroute_hops'][target],
                'subdomain_count': len(self.metrics['subdomains'][target]),
                'security_score': self.metrics['security_score'][target]
            }
            data_list.append(target_data)
        
        # Convert to DataFrame
        df = pd.DataFrame(data_list)
        
        # List of features for regression
        features = ['ports_open', 'vulns_found', 'response_time', 'traceroute_hops', 'subdomain_count']
        
        return df, features

class RegressionAnalyzer:
    """
    Performs regression analysis on network scan metrics
    """
    def __init__(self, data: pd.DataFrame, features: List[str], target_col: str = 'security_score'):
        self.data = data
        self.features = features
        self.target_col = target_col
        self.model = LinearRegression()
        self.coefficients = {}
        self.mse = 0
        self.r2 = 0
        logging.info(f"RegressionAnalyzer initialized with target column: {target_col} and features: {features}")
    
    def perform_regression(self) -> Dict:
        """Perform regression analysis on the data"""
        logging.info("Performing regression analysis")
        if len(self.data) < 2:
            logging.warning("Insufficient data for regression analysis. Need at least 2 samples.")
            return None
        
        # Prepare data
        X = self.data[self.features]
        y = self.data[self.target_col]
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Fit model
        self.model.fit(X_scaled, y)
        
        # Make predictions
        y_pred = self.model.predict(X_scaled)
        
        # Calculate metrics
        self.mse = mean_squared_error(y, y_pred)
        self.r2 = r2_score(y, y_pred)
        
        # Store coefficients
        for i, feature in enumerate(self.features):
            self.coefficients[feature] = self.model.coef_[i]
        
        # Prepare results
        results = {
            'coefficients': self.coefficients,
            'mse': self.mse,
            'r2': self.r2,
            'importance': sorted([(feat, abs(coef)) for feat, coef in self.coefficients.items()], 
                                key=lambda x: x[1], reverse=True)
        }
        
        logging.info(f"Regression analysis completed with results: {results}")
        return results

class NetworkVisualizer:
    """
    Creates visual representations of network reconnaissance data
    """
    def __init__(self, metrics: Dict, output_dir: str = "visual_reports"):
        self.metrics = metrics
        self.output_dir = output_dir
        self.report_data = {}
        logging.info(f"NetworkVisualizer initialized with output directory: {output_dir}")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def create_open_ports_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a bar chart showing open ports by target"""
        logging.info(f"Creating open ports chart for targets: {targets}")
        if not targets:
            targets = list(self.metrics['ports'].keys())
        
        # Count open ports for each target
        port_counts = {target: len(ports) for target, ports in self.metrics['ports'].items() if target in targets}
        
        # Sort data for better visualization
        sorted_items = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color='cornflowerblue'
        ))
        
        fig.update_layout(
            title="Open Ports by Target",
            xaxis_title="Target",
            yaxis_title="Number of Open Ports",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "open_ports_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Open Ports by Target'
        }
        
        self.report_data['open_ports_chart'] = result
        logging.info("Open ports chart created")
        return result
    
    def create_vulnerability_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a bar chart showing vulnerabilities by target"""
        logging.info(f"Creating vulnerability chart for targets: {targets}")
        if not targets:
            targets = list(self.metrics['vulnerabilities'].keys())
        
        # Count vulnerabilities for each target
        vuln_counts = {target: len(vulns) for target, vulns in self.metrics['vulnerabilities'].items() if target in targets}
        
        # Create color scale based on severity (more vulnerabilities = more severe)
        max_vulns = max(vuln_counts.values()) if vuln_counts else 1
        colors = [f'rgba(255, {max(0, 255 - int(255 * count / max_vulns))}, 0, 0.7)' for count in vuln_counts.values()]
        
        # Sort data for better visualization
        sorted_items = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color=colors
        ))
        
        fig.update_layout(
            title="Vulnerabilities by Target",
            xaxis_title="Target",
            yaxis_title="Number of Vulnerabilities",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "vulnerability_chart.html")
               sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color=colors
        ))
        
        fig.update_layout(
            title="Vulnerabilities by Target",
            xaxis_title="Target",
            yaxis_title="Number of Vulnerabilities",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "vulnerability_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Vulnerabilities by Target'
        }
        
        self.report_data['vulnerability_chart'] = result
        logging.info("Vulnerability chart created")
        return result
    
    def create_security_score_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a gauge chart showing security scores by target"""
        logging.info(f"Creating security score chart for targets: {targets}")
        if not targets:
            targets = list(self.metrics['security_score'].keys())
        
        # Get security scores for each target
        scores = {target: score for target, score in self.metrics['security_score'].items() if target in targets}
        
        # Create subplots for each target
        fig = make_subplots(
            rows=1, 
            cols=len(scores),
            specs=[[{"type": "indicator"} for _ in range(len(scores))]],
            subplot_titles=list(scores.keys())
        )
        
        # Add a gauge for each target
        for i, (target, score) in enumerate(scores.items(), 1):
            # Determine color based on score
            if score >= 80:
                color = "green"
            elif score >= 60:
                color = "yellow"
            elif score >= 40:
                color = "orange"
            else:
                color = "red"
                
            fig.add_trace(
                go.Indicator(
                    mode="gauge+number",
                    value=score,
                    domain={'row': 0, 'column': i-1},
                    title={'text': f"{target}"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': color},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgray"},
                            {'range': [40, 60], 'color': "gray"},
                            {'range': [60, 80], 'color': "lightgray"},
                            {'range': [80, 100], 'color': "white"}
                        ]
                    }
                ),
                row=1, col=i
            )
        
        fig.update_layout(
            title_text="Security Scores by Target (Higher is Better)",
            height=400,
            width=250 * len(scores)
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "security_score_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        print(f"[+] Output file: {output_file}\n [+] {img_bytes} bytes") 

        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'gauge',
            'title': 'Security Scores by Target'
        }
        
        self.report_data['security_score_chart'] = result
        logging.info("Security score chart created")
        return result
    
    # Additional methods for other charts...

async def main():
    """Main function to demonstrate usage"""
    # Set up argument parser
    import argparse
    parser = argparse.ArgumentParser(description="Generate visual reports from network reconnaissance data")
    parser.add_argument("-t", "--targets", nargs="+", help="Target IP address(es) or domain(s) to include in the report")
    parser.add_argument("--results-dir", type=str, default="recon_results", help="Directory with scan results")
    parser.add_argument("--output-dir", type=str, default="visual_reports", help="Directory for output reports")
    parser.add_argument("--report-title", type=str, default="Network Reconnaissance Report", help="Title for the report")
    args = parser.parse_args()
    
    logging.info(f"Script started with arguments: {args}")
    
    # Ensure directories exist
    os.makedirs(args.results_dir, exist_ok=True)
    os.makedirs(args.output_dir, exist_ok=True)
    logging.info(f"Directories ensured: results_dir={args.results_dir}, output_dir={args.output_dir}")
    
    # Ask user if they want to perform a comprehensive scan
    target = args.targets[0] if args.targets else None
    if target:
        comprehensive_scan = input(f"Do you want to perform a comprehensive full scan on {target}? (yes/no): ").strip().lower()
        logging.info(f"User chose to perform comprehensive scan: {comprehensive_scan}")
        if comprehensive_scan == "yes":
            print("Warning: This scan will be extremely slow, especially through proxy chains.")
            comprehensive_result = run_comprehensive_scan(target)
            if comprehensive_result:
                # Save comprehensive scan result to a file
                result_file = os.path.join(args.results_dir, f"{target}_comprehensive.json")
                with open(result_file, 'w') as f:
                    json.dump({"target": target, "output": comprehensive_result}, f)
                print(f"Comprehensive scan results saved to {result_file}")
                logging.info(f"Comprehensive scan results saved to {result_file}")

    # Process data
    logging.info(f"Processing data for target: {target}")
    processor = NetworkDataProcessor(args.results_dir)
    await processor.load_scan_results(target)
    metrics = processor.extract_metrics()
    
    # Create visualizations
    logging.info("Creating visualizations")
    visualizer = NetworkVisualizer(metrics, args.output_dir)
    charts = visualizer.generate_all_charts(args.targets)
    
    # Run regression analysis if enough targets
    regression_results = None
    if len(metrics['security_score']) >= 2:
        df, features = processor.prepare_data_for_regression()
        analyzer = RegressionAnalyzer(df, features)
        regression_results = analyzer.perform_regression()
        if regression_results:
            visualizer.create_regression_chart(regression_results, df)
    
    # Generate HTML report
    logging.info("Generating HTML report")
    report_generator = HTMLReportGenerator(metrics, charts, regression_results)
    report_file = os.path.join(args.output_dir, f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    output_file = report_generator.generate_html_report(report_file, args.report_title)
    
    print(f"Report generated successfully: {output_file}")
    logging.info(f"Report generated successfully: {output_file}")

if __name__ == "__main__":
    asyncio.run(main())
