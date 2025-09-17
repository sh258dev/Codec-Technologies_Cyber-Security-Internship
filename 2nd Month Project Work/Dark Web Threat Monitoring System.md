Dark Web Threat Monitoring System
Overview
A comprehensive Python-based system for monitoring dark web marketplaces, forums, and paste sites to detect leaked credentials, exploits, and organization-specific threats using Tor anonymity and natural language processing.

System Architecture

# dark_web_monitor.py
import os
import sys
import time
import json
import requests
from bs4 import BeautifulSoup
import stem.process
from stem.control import Controller
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.sentiment import SentimentIntensityAnalyzer
import re
import sqlite3
from datetime import datetime
import logging

# Download NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('vader_lexicon')

class DarkWebMonitor:
    def __init__(self, organization_keywords=None):
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.tor_process = None
        self.session = self.create_tor_session()
        self.keywords = organization_keywords or []
        self.sia = SentimentIntensityAnalyzer()
        self.setup_logging()
        self.setup_database()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dark_web_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_database(self):
        self.conn = sqlite3.connect('threat_intel.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY,
                source TEXT,
                content TEXT,
                threat_type TEXT,
                confidence REAL,
                timestamp DATETIME,
                keywords_found TEXT,
                sentiment_score REAL
            )
        ''')
        self.conn.commit()

Tor Connection Management

# tor_manager.py
import stem
from stem.control import Controller
import requests

class TorManager:
    def __init__(self):
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.tor_process = None
        
    def start_tor(self):
        """Start Tor process"""
        try:
            self.tor_process = stem.process.launch_tor_with_config(
                config={
                    'SocksPort': str(self.tor_port),
                    'ControlPort': str(self.tor_control_port),
                }
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")
            return False
    
    def create_tor_session(self):
        """Create requests session with Tor proxy"""
        session = requests.Session()
        session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        }
        return session
    
    def renew_identity(self):
        """Renew Tor circuit for new identity"""
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)
            return True
        except Exception as e:
            self.logger.error(f"Failed to renew identity: {e}")
            return False
    
    def stop_tor(self):
        """Stop Tor process"""
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process.wait()

Dark Web Scrapers

# scrapers.py
import time
from bs4 import BeautifulSoup
import re

class DarkWebScrapers:
    def __init__(self, session):
        self.session = session
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
    
    def scrape_marketplace(self, url):
        """Scrape dark web marketplace"""
        try:
            response = self.session.get(url, headers=self.headers, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract listings (adjust selectors based on actual marketplace)
            listings = []
            for listing in soup.select('.listing'):
                title = listing.select_one('.title').text.strip() if listing.select_one('.title') else ''
                description = listing.select_one('.description').text.strip() if listing.select_one('.description') else ''
                price = listing.select_one('.price').text.strip() if listing.select_one('.price') else ''
                
                listings.append({
                    'title': title,
                    'description': description,
                    'price': price,
                    'url': url
                })
            
            return listings
            
        except Exception as e:
            self.logger.error(f"Error scraping {url}: {e}")
            return []
    
    def scrape_forum(self, url):
        """Scrape dark web forum"""
        try:
            response = self.session.get(url, headers=self.headers, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            threads = []
            for thread in soup.select('.thread'):
                title = thread.select_one('.thread-title').text.strip() if thread.select_one('.thread-title') else ''
                content = thread.select_one('.thread-content').text.strip() if thread.select_one('.thread-content') else ''
                author = thread.select_one('.author').text.strip() if thread.select_one('.author') else ''
                
                threads.append({
                    'title': title,
                    'content': content,
                    'author': author,
                    'url': url
                })
            
            return threads
            
        except Exception as e:
            self.logger.error(f"Error scraping forum {url}: {e}")
            return []
    
    def scrape_paste_site(self, url):
        """Scrape paste sites for leaked data"""
        try:
            response = self.session.get(url, headers=self.headers, timeout=30)
            content = response.text
            
            # Look for common patterns in leaked data
            patterns = {
                'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'credit_cards': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
                'credentials': r'(?i)(username|password|login|credential)[:\s]+([^\s]+)'
            }
            
            findings = {}
            for key, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings[key] = matches
            
            return {
                'content': content[:1000] + '...' if len(content) > 1000 else content,
                'findings': findings,
                'url': url
            }
            
        except Exception as e:
            self.logger.error(f"Error scraping paste site {url}: {e}")
            return {} 

Threat Analysis Engine 

# analysis_engine.py
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.sentiment import SentimentIntensityAnalyzer
import re

class ThreatAnalyzer:
    def __init__(self, keywords):
        self.keywords = [k.lower() for k in keywords]
        self.sia = SentimentIntensityAnalyzer()
        self.stop_words = set(stopwords.words('english'))
        
    def analyze_content(self, content, source):
        """Analyze content for threats and keywords"""
        text = f"{content.get('title', '')} {content.get('description', '')} {content.get('content', '')}"
        text = text.lower()
        
        # Keyword matching
        found_keywords = [kw for kw in self.keywords if kw in text]
        
        # Threat type classification
        threat_type = self.classify_threat(text)
        
        # Sentiment analysis
        sentiment = self.sia.polarity_scores(text)
        
        # Confidence score
        confidence = self.calculate_confidence(text, found_keywords, threat_type)
        
        return {
            'threat_type': threat_type,
            'confidence': confidence,
            'keywords_found': found_keywords,
            'sentiment_score': sentiment['compound'],
            'source': source
        }
    
    def classify_threat(self, text):
        """Classify the type of threat"""
        threat_patterns = {
            'credentials': r'(password|login|credential|account|auth)',
            'exploit': r'(exploit|vulnerability|cve|0day|rce)',
            'malware': r'(malware|ransomware|trojan|virus|botnet)',
            'data_breach': r'(breach|leak|dump|database|records)',
            'financial': r'(credit card|bank|payment|financial|fraud)'
        }
        
        for threat_type, pattern in threat_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return threat_type
        
        return 'unknown'
    
    def calculate_confidence(self, text, found_keywords, threat_type):
        """Calculate confidence score for threat detection"""
        confidence = 0.0
        
        # Base confidence based on threat type
        threat_weights = {
            'credentials': 0.8,
            'exploit': 0.9,
            'malware': 0.7,
            'data_breach': 0.85,
            'financial': 0.75,
            'unknown': 0.3
        }
        
        confidence += threat_weights.get(threat_type, 0.3)
        
        # Add weight for each keyword found
        confidence += min(0.3, len(found_keywords) * 0.1)
        
        # Add weight for specific patterns
        if re.search(r'\b(urgent|critical|immediate)\b', text, re.IGNORECASE):
            confidence += 0.1
        
        return min(0.99, confidence) 

Main Monitoring System

# main.py
from datetime import datetime
import time
import json

class DarkWebMonitoringSystem:
    def __init__(self, config_file='config.json'):
        self.config = self.load_config(config_file)
        self.tor_manager = TorManager()
        self.scrapers = None
        self.analyzer = None
        self.monitoring = False
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        default_config = {
            "organization_keywords": ["company", "enterprise", "corp"],
            "monitor_sites": [
                "http://exampleonionmarket.onion",
                "http://exampleforum.onion",
                "http://examplepastesite.onion"
            ],
            "scan_interval": 3600,  # 1 hour
            "alert_threshold": 0.7
        }
        
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return default_config
    
    def initialize(self):
        """Initialize the monitoring system"""
        try:
            # Start Tor
            if not self.tor_manager.start_tor():
                raise Exception("Failed to start Tor")
            
            # Create session and components
            session = self.tor_manager.create_tor_session()
            self.scrapers = DarkWebScrapers(session)
            self.analyzer = ThreatAnalyzer(self.config['organization_keywords'])
            
            self.logger.info("Dark Web Monitoring System initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def monitor_loop(self):
        """Main monitoring loop"""
        self.monitoring = True
        self.logger.info("Starting monitoring loop...")
        
        while self.monitoring:
            try:
                self.scan_sites()
                time.sleep(self.config['scan_interval'])
                
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def scan_sites(self):
        """Scan all configured sites"""
        self.logger.info("Starting site scan...")
        
        for site in self.config['monitor_sites']:
            try:
                self.logger.info(f"Scanning {site}")
                
                # Determine site type and scrape accordingly
                if 'market' in site:
                    content = self.scrapers.scrape_marketplace(site)
                elif 'forum' in site:
                    content = self.scrapers.scrape_forum(site)
                elif 'paste' in site:
                    content = self.scrapers.scrape_paste_site(site)
                else:
                    content = self.scrapers.scrape_general(site)
                
                # Analyze content
                for item in content:
                    analysis = self.analyzer.analyze_content(item, site)
                    
                    # Store and alert if necessary
                    if analysis['confidence'] > self.config['alert_threshold']:
                        self.store_threat(item, analysis)
                        self.send_alert(item, analysis)
                
                # Renew Tor identity periodically
                self.tor_manager.renew_identity()
                
            except Exception as e:
                self.logger.error(f"Error scanning {site}: {e}")
    
    def store_threat(self, content, analysis):
        """Store threat in database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (source, content, threat_type, confidence, timestamp, keywords_found, sentiment_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis['source'],
                str(content),
                analysis['threat_type'],
                analysis['confidence'],
                datetime.now(),
                str(analysis['keywords_found']),
                analysis['sentiment_score']
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing threat: {e}")
    
    def send_alert(self, content, analysis):
        """Send alert for high-confidence threats"""
        alert_message = f"""
        🚨 DARK WEB THREAT ALERT 🚨
        
        Source: {analysis['source']}
        Threat Type: {analysis['threat_type']}
        Confidence: {analysis['confidence']:.2f}
        Keywords Found: {', '.join(analysis['keywords_found'])}
        
        Content Preview:
        {str(content)[:500]}...
        
        Timestamp: {datetime.now()}
        """
        
        self.logger.warning(alert_message)
        # Here you could add email/SMS/API notifications
    
    def shutdown(self):
        """Clean shutdown"""
        self.monitoring = False
        self.tor_manager.stop_tor()
        self.conn.close()
        self.logger.info("System shutdown complete")

# Usage
if __name__ == "__main__":
    monitor = DarkWebMonitoringSystem()
    
    if monitor.initialize():
        try:
            monitor.monitor_loop()
        except KeyboardInterrupt:
            pass
        finally:
            monitor.shutdown() 

Configuration File 

{
    "organization_keywords": [
        "yourcompany",
        "yourbrand",
        "ceo_name",
        "product_names"
    ],
    "monitor_sites": [
        "http://knownmarketplace.onion",
        "http://hackerforum.onion",
        "http://pastebin.onion"
    ],
    "scan_interval": 3600,
    "alert_threshold": 0.7,
    "notification_emails": ["security@yourcompany.com"],
    "sms_alerts": ["+1234567890"]
} 


Installation and Setup 

# Install required packages
pip install requests beautifulsoup4 stem nltk scrapy sqlite3

# Install Tor
# On Ubuntu/Debian:
sudo apt-get install tor

# On macOS:
brew install tor

# On Windows: Download from torproject.org

# Initialize the system
python main.py 


Key Features
Anonymity: Uses Tor for anonymous dark web access

Multiple Scrapers: Handles marketplaces, forums, and paste sites

Threat Analysis: NLP-based keyword matching and sentiment analysis

Alert System: Configurable threshold-based alerts

Persistence: SQLite database for threat storage

Resilience: Error handling and Tor circuit renewal

Important Notes
⚠️ Legal Compliance: Ensure you have proper authorization before monitoring

⚠️ Ethical Considerations: Respect privacy and legal boundaries

🔒 Security: Run in isolated environment with proper security measures

📊 Customization: Adjust keywords and sites based on your organization's needs

This system provides a foundation for dark web monitoring that can be extended with additional features like machine learning classification, real-time alerts, and integration with existing security systems.