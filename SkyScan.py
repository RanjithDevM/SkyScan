#!/usr/bin/env python3
"""
Enhanced Interactive Nuclei-Inspired Vulnerability Scanner
A comprehensive Python implementation with cloud environment support
"""

import asyncio
import aiohttp
import json
import yaml
import sys
import os
import socket
import ssl
import ipaddress
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import re
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import requests

# Try to import optional dependencies
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

@dataclass
class ScanResult:
    """Represents a scan result"""
    target: str
    template: str
    severity: str
    matched: bool
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    matched_text: Optional[str] = None
    error: Optional[str] = None
    extracted_data: Optional[str] = None
    extracted_file: Optional[str] = None
    cloud_metadata: Optional[Dict[str, Any]] = None
    ssl_info: Optional[Dict[str, Any]] = None
    dns_info: Optional[Dict[str, Any]] = None
    match_detail: Optional[str] = None
    cloud_service: Optional[str] = None

@dataclass
class CloudService:
    """Cloud service information"""
    provider: str
    service_type: str
    region: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class CloudDetector:
    """Detects and analyzes cloud services"""
    
    def __init__(self):
        self.aws_indicators = [
            'amazonaws.com', 's3.amazonaws.com', 'cloudfront.net', 'elb.amazonaws.com',
            'rds.amazonaws.com', 'ec2.amazonaws.com', 'lambda.amazonaws.com'
        ]
        self.azure_indicators = [
            'azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'servicebus.windows.net',
            'database.windows.net', 'vault.azure.net'
        ]
        self.gcp_indicators = [
            'googleapis.com', 'googleusercontent.com', 'appspot.com', 'cloudfunctions.net',
            'run.app', 'firestore.googleapis.com'
        ]
        
    async def detect_cloud_service(self, url: str, session: aiohttp.ClientSession) -> Optional[CloudService]:
        """Detect cloud service provider and type"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            
            # Check headers and responses for cloud indicators
            async with session.get(url, timeout=10) as response:
                headers = dict(response.headers)
                content = await response.text()
                
                # AWS Detection
                if any(indicator in hostname for indicator in self.aws_indicators):
                    return await self._analyze_aws_service(hostname, headers, content, response)
                
                # Azure Detection
                elif any(indicator in hostname for indicator in self.azure_indicators):
                    return await self._analyze_azure_service(hostname, headers, content, response)
                
                # GCP Detection
                elif any(indicator in hostname for indicator in self.gcp_indicators):
                    return await self._analyze_gcp_service(hostname, headers, content, response)
                
                # Generic cloud detection via headers
                else:
                    return await self._detect_via_headers(hostname, headers, content)
                    
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Cloud detection failed for {url}: {e}{Colors.END}")
            return None
    
    def _detect_cloud_service(self, url: str) -> Optional[str]:
        """Simple cloud service detection for basic usage"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            
            if any(indicator in hostname for indicator in self.aws_indicators):
                return "AWS"
            elif any(indicator in hostname for indicator in self.azure_indicators):
                return "Azure"
            elif any(indicator in hostname for indicator in self.gcp_indicators):
                return "GCP"
            
            return None
        except:
            return None
    
    async def _analyze_aws_service(self, hostname: str, headers: Dict, content: str, response) -> CloudService:
        """Analyze AWS-specific service"""
        metadata = {}
        service_type = "Unknown AWS Service"
        region = None
        
        # S3 Bucket Detection
        if 's3' in hostname or 'bucket' in content.lower():
            service_type = "S3 Bucket"
            metadata['bucket_name'] = hostname.split('.')[0] if '.' in hostname else 'unknown'
            
            # Try to detect region from headers or URL structure
            if 'x-amz-bucket-region' in headers:
                region = headers['x-amz-bucket-region']
            elif '-' in hostname:
                parts = hostname.split('.')
                for part in parts:
                    if any(r in part for r in ['us-east', 'us-west', 'eu-', 'ap-', 'sa-', 'ca-']):
                        region = part
                        break
        
        # CloudFront Detection
        elif 'cloudfront' in hostname:
            service_type = "CloudFront Distribution"
            if 'x-amz-cf-id' in headers:
                metadata['distribution_id'] = headers['x-amz-cf-id']
        
        # ELB Detection
        elif 'elb' in hostname:
            service_type = "Elastic Load Balancer"
            
        # Lambda Detection
        elif 'lambda' in hostname or 'execute-api' in hostname:
            service_type = "Lambda Function/API Gateway"
        
        # EC2 Detection
        elif 'compute' in hostname or response.status == 200:
            if 'server' in headers and 'ec2' in headers['server'].lower():
                service_type = "EC2 Instance"
        
        # Add security headers analysis
        security_headers = self._analyze_security_headers(headers)
        if security_headers:
            metadata['security_headers'] = security_headers
            
        return CloudService("AWS", service_type, region, metadata)
    
    async def _analyze_azure_service(self, hostname: str, headers: Dict, content: str, response) -> CloudService:
        """Analyze Azure-specific service"""
        metadata = {}
        service_type = "Unknown Azure Service"
        region = None
        
        if 'blob.core.windows.net' in hostname:
            service_type = "Azure Blob Storage"
            metadata['storage_account'] = hostname.split('.')[0]
            
        elif 'azurewebsites.net' in hostname:
            service_type = "Azure App Service"
            if 'x-powered-by' in headers:
                metadata['runtime'] = headers['x-powered-by']
                
        elif 'database.windows.net' in hostname:
            service_type = "Azure SQL Database"
            
        elif 'vault.azure.net' in hostname:
            service_type = "Azure Key Vault"
        
        # Add security analysis
        security_headers = self._analyze_security_headers(headers)
        if security_headers:
            metadata['security_headers'] = security_headers
            
        return CloudService("Azure", service_type, region, metadata)
    
    async def _analyze_gcp_service(self, hostname: str, headers: Dict, content: str, response) -> CloudService:
        """Analyze GCP-specific service"""
        metadata = {}
        service_type = "Unknown GCP Service"
        region = None
        
        if 'appspot.com' in hostname:
            service_type = "Google App Engine"
            metadata['project_id'] = hostname.split('.')[0]
            
        elif 'cloudfunctions.net' in hostname:
            service_type = "Google Cloud Functions"
            
        elif 'run.app' in hostname:
            service_type = "Google Cloud Run"
            
        elif 'googleapis.com' in hostname:
            service_type = "Google API Service"
            
        # Add security analysis
        security_headers = self._analyze_security_headers(headers)
        if security_headers:
            metadata['security_headers'] = security_headers
            
        return CloudService("GCP", service_type, region, metadata)
    
    async def _detect_via_headers(self, hostname: str, headers: Dict, content: str) -> Optional[CloudService]:
        """Detect cloud services via response headers"""
        cloud_indicators = {
            'AWS': ['x-amz-', 'amazon', 'aws'],
            'Azure': ['x-ms-', 'microsoft', 'azure'],
            'GCP': ['x-goog-', 'google', 'gcp'],
            'Cloudflare': ['cf-', 'cloudflare'],
            'Fastly': ['fastly', 'x-served-by'],
            'Akamai': ['akamai', 'x-akamai']
        }
        
        for provider, indicators in cloud_indicators.items():
            for header, value in headers.items():
                if any(indicator in header.lower() or indicator in str(value).lower() 
                      for indicator in indicators):
                    metadata = {'detected_via': 'headers', 'header': header, 'value': str(value)}
                    security_headers = self._analyze_security_headers(headers)
                    if security_headers:
                        metadata['security_headers'] = security_headers
                    return CloudService(provider, "Detected via Headers", None, metadata)
        
        return None
    
    def _analyze_security_headers(self, headers: Dict) -> Dict[str, Any]:
        """Analyze security-related headers"""
        security_analysis = {}
        
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy'
        }
        
        missing_headers = []
        present_headers = {}
        
        for header, name in security_headers.items():
            if header in headers:
                present_headers[name] = headers[header]
            else:
                missing_headers.append(name)
        
        security_analysis['present'] = present_headers
        security_analysis['missing'] = missing_headers
        security_analysis['security_score'] = len(present_headers) / len(security_headers) * 100
        
        return security_analysis

class AWSScanner:
    """AWS-specific security scanner"""
    
    def __init__(self):
        self.s3_client = None
        self.ec2_client = None
        
    async def initialize_clients(self):
        """Initialize AWS clients if credentials are available"""
        if not AWS_AVAILABLE:
            return False
            
        try:
            # Try to initialize AWS clients
            self.s3_client = boto3.client('s3')
            self.ec2_client = boto3.client('ec2')
            return True
        except (NoCredentialsError, Exception):
            return False
    
    async def scan_s3_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Scan S3 bucket for misconfigurations"""
        if not self.s3_client:
            return {'error': 'AWS credentials not available'}
        
        results = {}
        try:
            # Check bucket policy
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                results['bucket_policy'] = json.loads(policy['Policy'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    results['bucket_policy'] = 'No bucket policy found'
                else:
                    results['bucket_policy_error'] = str(e)
            
            # Check public access block
            try:
                pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                results['public_access_block'] = pab['PublicAccessBlockConfiguration']
            except ClientError as e:
                results['public_access_block_error'] = str(e)
            
            # Check bucket ACL
            try:
                acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                results['bucket_acl'] = acl
            except ClientError as e:
                results['bucket_acl_error'] = str(e)
                
        except Exception as e:
            results['error'] = str(e)
        
        return results

class DNSAnalyzer:
    """DNS analysis and reconnaissance"""
    
    def __init__(self):
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
        else:
            self.resolver = None
        
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS analysis"""
        if not DNS_AVAILABLE:
            return {'error': 'DNS library not available'}
            
        dns_info = {}
        
        try:
            # A records
            try:
                a_records = self.resolver.resolve(domain, 'A')
                dns_info['A'] = [str(record) for record in a_records]
            except:
                dns_info['A'] = []
            
            # AAAA records
            try:
                aaaa_records = self.resolver.resolve(domain, 'AAAA')
                dns_info['AAAA'] = [str(record) for record in aaaa_records]
            except:
                dns_info['AAAA'] = []
            
            # MX records
            try:
                mx_records = self.resolver.resolve(domain, 'MX')
                dns_info['MX'] = [f"{record.preference} {record.exchange}" for record in mx_records]
            except:
                dns_info['MX'] = []
            
            # TXT records
            try:
                txt_records = self.resolver.resolve(domain, 'TXT')
                dns_info['TXT'] = [str(record) for record in txt_records]
            except:
                dns_info['TXT'] = []
            
            # CNAME records
            try:
                cname_records = self.resolver.resolve(domain, 'CNAME')
                dns_info['CNAME'] = [str(record) for record in cname_records]
            except:
                dns_info['CNAME'] = []
            
            # NS records
            try:
                ns_records = self.resolver.resolve(domain, 'NS')
                dns_info['NS'] = [str(record) for record in ns_records]
            except:
                dns_info['NS'] = []
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info

class SSLAnalyzer:
    """SSL/TLS certificate analysis"""
    
    async def analyze_ssl(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL certificate and configuration"""
        ssl_info = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_name': cert.get('subjectAltName', [])
                    }
                    
                    ssl_info['connection'] = {
                        'protocol': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'cipher_strength': cipher[1] if cipher else None
                    }
                    
                    # Check for vulnerabilities
                    vulnerabilities = []
                    if version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append('Weak TLS version')
                    
                    if cipher and any(weak in cipher[0].lower() for weak in ['rc4', 'des', 'md5']):
                        vulnerabilities.append('Weak cipher suite')
                    
                    ssl_info['vulnerabilities'] = vulnerabilities
                    
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info

class TemplateEngine:
    """Enhanced template loading and parsing with cloud templates"""
    
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.templates = []
        
    def load_templates(self) -> List[Dict[str, Any]]:
        """Load all YAML templates from the template directory"""
        templates = []
        
        if not self.template_dir.exists():
            print(f"{Colors.YELLOW}Template directory not found. Creating sample templates...{Colors.END}")
            self._create_sample_templates()
            
        for template_file in self.template_dir.glob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    template = yaml.safe_load(f)
                    templates.append(template)
            except Exception as e:
                print(f"{Colors.RED}Error loading template {template_file}: {e}{Colors.END}")
                
        return templates
    
    def _create_sample_templates(self):
        """Create enhanced sample templates including cloud-specific ones"""
        self.template_dir.mkdir(exist_ok=True)
        
        templates = [
            # Admin Panel Detection
            {
                'id': 'admin-panel-detect',
                'info': {
                    'name': 'Admin Panel Detection',
                    'author': 'nuclei-mimic',
                    'severity': 'info',
                    'description': 'Detects common admin panel paths'
                },
                'requests': [{
                    'method': 'GET',
                    'path': ['/admin', '/admin.php', '/administrator', '/wp-admin', '/admin/login', '/panel', '/dashboard'],
                    'matchers': [{
                        'type': 'status',
                        'status': [200, 301, 302]
                    }]
                }]
            },
            
            # AWS S3 Bucket Enumeration
            {
                'id': 'aws-s3-bucket-enum',
                'info': {
                    'name': 'AWS S3 Bucket Enumeration',
                    'author': 'nuclei-mimic',
                    'severity': 'medium',
                    'description': 'Detects publicly accessible S3 buckets'
                },
                'requests': [{
                    'method': 'GET',
                    'path': ['/', '/?delimiter=/&prefix='],
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (compatible; S3Scanner/1.0)'
                    },
                    'matchers': [{
                        'type': 'word',
                        'words': ['<ListBucketResult', '<Error><Code>NoSuchBucket</Code>', 'AccessDenied']
                    }]
                }]
            },
            
            # Git Exposure
            {
                'id': 'git-exposure',
                'info': {
                    'name': 'Git Repository Exposure',
                    'author': 'nuclei-mimic',
                    'severity': 'medium',
                    'description': 'Detects exposed Git repositories'
                },
                'requests': [{
                    'method': 'GET',
                    'path': ['/.git/config', '/.git/HEAD', '/.git/index'],
                    'matchers': [{
                        'type': 'word',
                        'words': ['[core]', 'ref: refs/', 'repositoryformatversion']
                    }]
                }]
            },
        ]
        
        filenames = ['admin-panel.yaml', 'aws-s3-bucket.yaml', 'git-exposure.yaml']
        
        for template, filename in zip(templates, filenames):
            with open(self.template_dir / filename, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)

class EnhancedVulnerabilityScanner:
    """Enhanced scanner with cloud capabilities"""
    
    def __init__(self, concurrency: int = 10, timeout: int = 10, extract_data: bool = False, 
                 cloud_scan: bool = False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.extract_data = extract_data
        self.cloud_scan = cloud_scan
        self.template_engine = TemplateEngine()
        self.cloud_detector = CloudDetector()
        self.aws_scanner = AWSScanner()
        self.dns_analyzer = DNSAnalyzer()
        self.ssl_analyzer = SSLAnalyzer()
        self.results = []
        self.extracted_files_dir = Path("extracted_data")
        self.client = None
        
        if self.extract_data:
            self.extracted_files_dir.mkdir(exist_ok=True)
    
    async def scan_target(self, session: aiohttp.ClientSession, target: str, template: Dict[str, Any]) -> List[ScanResult]:
        """Enhanced target scanning with cloud analysis"""
        results = []
        
        for request in template.get('requests', []):
            method = request.get('method', 'GET')
            paths = request.get('path', ['/'])
            headers = request.get('headers', {})
            
            for path in paths:
                try:
                    start_time = time.time()
                    
                    # Handle absolute URLs in cloud metadata templates
                    if path.startswith('http'):
                        url = path
                    else:
                        url = urljoin(target, path)
                    
                    # Skip false positives for S3 buckets in admin-panel template
                    if template['id'] == 'admin-panel-detect':
                        if "s3.amazonaws.com" in url:
                            continue
                    
                    async with session.request(method, url, headers=headers, timeout=self.timeout) as response:
                        response_time = time.time() - start_time
                        content = await response.text()
                        
                        # Additional filtering for admin panels
                        if template['id'] == 'admin-panel-detect':
                            keywords = ["login", "username", "password", "admin"]
                            if not any(k in content.lower() for k in keywords):
                                continue
                        
                        matched, matched_text = self._check_matchers(
                            request.get('matchers', []), 
                            response, 
                            content
                        )
                        
                        # Cloud analysis
                        cloud_metadata = None
                        dns_info = None
                        ssl_info = None
                        
                        if self.cloud_scan and matched:
                            cloud_metadata = await self.cloud_detector.detect_cloud_service(url, session)
                            
                            # DNS analysis
                            parsed = urlparse(url)
                            if parsed.netloc:
                                dns_info = await self.dns_analyzer.analyze_domain(parsed.netloc.split(':')[0])
                            
                            # SSL analysis for HTTPS
                            if parsed.scheme == 'https':
                                ssl_info = await self.ssl_analyzer.analyze_ssl(parsed.netloc.split(':')[0])
                        
                        extracted_data = None
                        extracted_file = None
                        
                        # Enhanced data extraction
                        if matched and self.extract_data:
                            extracted_data, extracted_file = await self._extract_data(
                                session, url, template, content, response.status
                            )
                        
                        result = ScanResult(
                            target=url,
                            template=template['id'],
                            severity=template['info']['severity'],
                            matched=matched,
                            response_code=response.status,
                            response_time=response_time,
                            matched_text=matched_text,
                            extracted_data=extracted_data,
                            extracted_file=extracted_file,
                            cloud_metadata=cloud_metadata.__dict__ if cloud_metadata else None,
                            ssl_info=ssl_info,
                            dns_info=dns_info,
                            match_detail=matched_text,
                            cloud_service=self.cloud_detector._detect_cloud_service(url)
                        )
                        results.append(result)
                        
                        if matched:
                            self._print_enhanced_result(result, template)
                            
                except asyncio.TimeoutError:
                    result = ScanResult(
                        target=urljoin(target, path) if not path.startswith('http') else path,
                        template=template['id'],
                        severity=template['info']['severity'],
                        matched=False,
                        error="Timeout"
                    )
                    results.append(result)
                except Exception as e:
                    result = ScanResult(
                        target=urljoin(target, path) if not path.startswith('http') else path,
                        template=template['id'],
                        severity=template['info']['severity'],
                        matched=False,
                        error=str(e)
                    )
                    results.append(result)
                    
        return results
    
    def _check_matchers(self, matchers: List[Dict], response, content: str) -> tuple:
        """Enhanced matcher checking with improved false positive filtering"""
        for matcher in matchers:
            matcher_type = matcher.get('type')
            
            if matcher_type == 'status':
                if response.status in matcher.get('status', []):
                    # Prevent false positives on redirects for admin panels
                    if response.status in [301, 302]:
                        return False, None
                    return True, f"Status code: {response.status}"
                    
            elif matcher_type == 'word':
                words = matcher.get('words', [])
                for word in words:
                    if word.lower() in content.lower():
                        return True, f"Found word: {word}"
                        
            elif matcher_type == 'regex':
                patterns = matcher.get('regex', [])
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True, f"Regex match: {pattern}"
                        
        return False, None
    
    async def _extract_data(self, session: aiohttp.ClientSession, url: str, template: Dict, 
                           content: str, status_code: int) -> tuple:
        """Enhanced data extraction with cloud-specific analysis"""
        extracted_data = None
        extracted_file = None
        
        try:
            should_extract = status_code == 200 and len(content) > 0
            
            if should_extract:
                # Generate safe filename
                parsed = urlparse(url)
                domain = parsed.netloc.replace(':', '_').replace('.', '_')
                path_safe = parsed.path.replace('/', '_').replace('\\', '_')
                if not path_safe:
                    path_safe = 'index'
                
                filename = f"{domain}_{path_safe}_{int(time.time())}.txt"
                filepath = self.extracted_files_dir / filename
                
                # Create extraction report
                extraction_report = f"""
URL: {url}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Template: {template.get('id')}
Status Code: {status_code}
Content Length: {len(content)} bytes

Raw Content:
{content[:15000]}{'...[TRUNCATED]' if len(content) > 15000 else ''}
                """
                
                # Save extracted data
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(extraction_report)
                
                extracted_data = f"Extracted {len(content)} bytes"
                extracted_file = str(filepath)
                
                print(f"    {Colors.GREEN}💾 Data extracted: {filename}{Colors.END}")
                
        except Exception as e:
            print(f"    {Colors.RED}❌ Extraction failed: {str(e)}{Colors.END}")
        
        return extracted_data, extracted_file
    
    def _print_enhanced_result(self, result: ScanResult, template: Dict):
        """Prints enhanced results with filtering"""
        # Skip redirect-based admin panel detections
        if result.template == "admin-panel-detect" and result.response_code in [301, 302]:
            return

        severity_colors = {
            'info': Colors.BLUE,
            'low': Colors.GREEN,
            'medium': Colors.YELLOW,
            'high': Colors.RED,
            'critical': Colors.MAGENTA
        }
        
        color = severity_colors.get(result.severity, Colors.WHITE)
        
        print(f"{color}[{result.severity.upper()}]{Colors.END} {Colors.BOLD}{template['info']['name']}{Colors.END}")
        print(f"    {Colors.CYAN}Target:{Colors.END} {result.target}")
        print(f"    {Colors.CYAN}Template:{Colors.END} {result.template}")
        
        if result.matched_text:
            print(f"    {Colors.CYAN}Match:{Colors.END} {result.matched_text}")
        
        if result.response_time:
            print(f"    {Colors.CYAN}Response Time:{Colors.END} {result.response_time:.2f}s")
        
        if result.response_code:
            print(f"    {Colors.CYAN}Response Code:{Colors.END} {result.response_code}")
        
        # Cloud metadata information
        if result.cloud_metadata:
            print(f"    {Colors.MAGENTA}☁️  Cloud Service:{Colors.END} {result.cloud_metadata.get('provider')} - {result.cloud_metadata.get('service_type')}")
        
        if result.cloud_service:
            print(f"    {Colors.MAGENTA}☁️  Cloud Service:{Colors.END} {result.cloud_service}")
        
        if result.extracted_file:
            print(f"    {Colors.GREEN}💾 Extracted File:{Colors.END} {result.extracted_file}")
        
        print()
    
    async def scan_multiple_targets(self, targets: List[str], templates: List[Dict]) -> List[ScanResult]:
        """Enhanced multi-target scanning"""
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        # Initialize cloud services
        if self.cloud_scan:
            await self.aws_scanner.initialize_clients()
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            self.client = session  # Store session for compatibility
            tasks = []
            
            for target in targets:
                if not target.startswith(('http://', 'https://')):
                    target = 'http://' + target
                    
                for template in templates:
                    task = self.scan_target(session, target, template)
                    tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            all_results = []
            for result_list in results:
                if isinstance(result_list, list):
                    all_results.extend(result_list)
                elif isinstance(result_list, Exception):
                    print(f"[ERROR] Scan failed: {str(result_list)}")
                    
            return all_results

class InteractiveEnhancedScanner:
    """Enhanced interactive interface with cloud features"""
    
    def __init__(self):
        self.scanner = None
        
    def print_banner(self):
        """Print enhanced application banner"""
        banner = f"""
{Colors.GREEN} 
   .oooooo..o oooo                     .oooooo..o                                 
d8P'    `Y8 `888                    d8P'    `Y8                                 
Y88bo.       888  oooo  oooo    ooo Y88bo.       .ooooo.   .oooo.   ooo. .oo.   
 `"Y8888o.   888 .8P'    `88.  .8'   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b  
     `"Y88b  888888.      `88..8'        `"Y88b 888        .oP"888   888   888  
oo     .d8P  888 `88b.     `888'    oo     .d8P 888   .o8 d8(  888   888   888  
8""88888P'  o888o o888o     .8'     8""88888P'  `Y8bod8P' `Y888""8o o888o o888o 
                        .o..P'                                                  
                        `Y8P'                                                   
                                                                                   {Colors.END}
        """
        print(banner)
    
    def get_targets(self):
        """Get targets from user input"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Target Selection{Colors.END}")
        print("=" * 50)
        
        while True:
            print(f"\n{Colors.WHITE}How would you like to specify targets?{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} Enter a single URL")
            print(f"{Colors.GREEN}2.{Colors.END} Enter multiple URLs (comma-separated)")
            print(f"{Colors.GREEN}3.{Colors.END} Load targets from a file")
            print(f"{Colors.GREEN}4.{Colors.END} Use demo targets (for testing)")
            
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-4): {Colors.END}").strip()
            
            if choice == "1":
                target = input(f"{Colors.CYAN}Enter target URL: {Colors.END}").strip()
                if target:
                    return [target]
                    
            elif choice == "2":
                targets_input = input(f"{Colors.CYAN}Enter URLs (comma-separated): {Colors.END}").strip()
                if targets_input:
                    targets = [t.strip() for t in targets_input.split(',') if t.strip()]
                    return targets
                    
            elif choice == "3":
                filename = input(f"{Colors.CYAN}Enter filename: {Colors.END}").strip()
                try:
                    with open(filename, 'r') as f:
                        targets = [line.strip() for line in f if line.strip()]
                    if targets:
                        print(f"{Colors.GREEN}Loaded {len(targets)} targets from file{Colors.END}")
                        return targets
                    else:
                        print(f"{Colors.RED}File is empty or invalid{Colors.END}")
                except FileNotFoundError:
                    print(f"{Colors.RED}File not found{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}Error reading file: {e}{Colors.END}")
                    
            elif choice == "4":
                demo_targets = [
                    "https://httpbin.org",
                    "https://example.com",
                    "http://testphp.vulnweb.com"
                ]
                print(f"{Colors.GREEN}Using demo targets:{Colors.END}")
                for target in demo_targets:
                    print(f"  • {target}")
                return demo_targets
                
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")

    def select_templates(self, available_templates):
        """Let user select which templates to use"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Template Selection{Colors.END}")
        print("=" * 50)
        
        print(f"\n{Colors.WHITE}Available templates:{Colors.END}")
        for i, template in enumerate(available_templates, 1):
            severity_colors = {
                'info': Colors.BLUE,
                'low': Colors.GREEN,
                'medium': Colors.YELLOW,
                'high': Colors.RED,
                'critical': Colors.MAGENTA
            }
            color = severity_colors.get(template['info']['severity'], Colors.WHITE)
            print(f"{Colors.GREEN}{i:2}.{Colors.END} {Colors.BOLD}{template['info']['name']}{Colors.END}")
            print(f"     {color}[{template['info']['severity'].upper()}]{Colors.END} {template['info']['description']}")
            print()
        
        while True:
            print(f"{Colors.WHITE}Template selection options:{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} Use all templates")
            print(f"{Colors.GREEN}2.{Colors.END} Select specific templates")
            print(f"{Colors.GREEN}3.{Colors.END} Filter by severity level")
            
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-3): {Colors.END}").strip()
            
            if choice == "1":
                return available_templates
                
            elif choice == "2":
                selected_input = input(f"{Colors.CYAN}Enter template numbers (comma-separated): {Colors.END}").strip()
                try:
                    selected_numbers = [int(x.strip()) for x in selected_input.split(',')]
                    selected_templates = []
                    for num in selected_numbers:
                        if 1 <= num <= len(available_templates):
                            selected_templates.append(available_templates[num-1])
                    if selected_templates:
                        return selected_templates
                    else:
                        print(f"{Colors.RED}No valid templates selected{Colors.END}")
                except ValueError:
                    print(f"{Colors.RED}Invalid input format{Colors.END}")
                    
            elif choice == "3":
                print(f"\n{Colors.WHITE}Select severity level:{Colors.END}")
                severities = list(set(t['info']['severity'] for t in available_templates))
                for i, severity in enumerate(severities, 1):
                    print(f"{Colors.GREEN}{i}.{Colors.END} {severity}")
                
                sev_choice = input(f"{Colors.CYAN}Enter choice: {Colors.END}").strip()
                try:
                    selected_severity = severities[int(sev_choice)-1]
                    filtered_templates = [t for t in available_templates if t['info']['severity'] == selected_severity]
                    if filtered_templates:
                        return filtered_templates
                except (ValueError, IndexError):
                    print(f"{Colors.RED}Invalid choice{Colors.END}")
                    
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")

    def get_scan_settings(self) -> tuple:
        """Get enhanced scan configuration"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}⚙️  ENHANCED SCAN CONFIGURATION{Colors.END}")
        print("=" * 60)
        
        # Concurrency
        while True:
            concurrency_input = input(f"{Colors.CYAN}Concurrent threads (default 10): {Colors.END}").strip()
            if not concurrency_input:
                concurrency = 10
                break
            try:
                concurrency = int(concurrency_input)
                if 1 <= concurrency <= 100:
                    break
                else:
                    print(f"{Colors.RED}❌ Please enter a number between 1 and 100{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}❌ Please enter a valid number{Colors.END}")
        
        # Timeout
        while True:
            timeout_input = input(f"{Colors.CYAN}Request timeout in seconds (default 10): {Colors.END}").strip()
            if not timeout_input:
                timeout = 10
                break
            try:
                timeout = int(timeout_input)
                if 1 <= timeout <= 60:
                    break
                else:
                    print(f"{Colors.RED}❌ Please enter a number between 1 and 60{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}❌ Please enter a valid number{Colors.END}")
        
        # Data extraction
        while True:
            extract_choice = input(f"{Colors.CYAN}Enable enhanced data extraction? (y/N): {Colors.END}").strip().lower()
            if extract_choice in ['', 'n', 'no']:
                extract_data = False
                break
            elif extract_choice in ['y', 'yes']:
                extract_data = True
                print(f"{Colors.GREEN}✓ Enhanced data extraction enabled{Colors.END}")
                break
            else:
                print(f"{Colors.RED}❌ Please enter 'y' or 'n'{Colors.END}")
        
        # Cloud scanning
        while True:
            cloud_choice = input(f"{Colors.CYAN}Enable cloud environment analysis? (Y/n): {Colors.END}").strip().lower()
            if cloud_choice in ['', 'y', 'yes']:
                cloud_scan = True
                print(f"{Colors.GREEN}✓ Cloud analysis enabled{Colors.END}")
                break
            elif cloud_choice in ['n', 'no']:
                cloud_scan = False
                break
            else:
                print(f"{Colors.RED}❌ Please enter 'y' or 'n'{Colors.END}")
        
        # Output file
        output_file = input(f"{Colors.CYAN}Save results to file (optional): {Colors.END}").strip()
        if not output_file:
            output_file = None
            
        return concurrency, timeout, extract_data, cloud_scan, output_file

    def show_help(self):
        """Display comprehensive help information"""
        help_text = f"""
{Colors.BOLD}Enhanced Nuclei-Inspired Vulnerability Scanner{Colors.END}

This tool provides comprehensive security testing capabilities for web applications
and cloud environments, inspired by the popular Nuclei scanner.

{Colors.BOLD}Key Features:{Colors.END}
• Web application vulnerability scanning
• Cloud service detection and analysis (AWS, Azure, GCP)
• SSL/TLS certificate validation
• DNS reconnaissance and analysis
• Enhanced data extraction and analysis
• Interactive menu system with detailed reporting

{Colors.BOLD}Usage Tips:{Colors.END}
• Start with demo targets to test the tool
• Enable cloud analysis for comprehensive testing
• Use data extraction to capture detailed findings
• Only test systems you own or have permission to test

{Colors.BOLD}Dependencies:{Colors.END}
• Python 3.7+
• aiohttp, PyYAML, dnspython, boto3
• Install with: pip install aiohttp pyyaml dnspython boto3
        """
        print(help_text)

    def wait_for_user(self):
        """Wait for user input"""
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

    def perform_scan(self):
        """Perform enhanced scan workflow"""
        try:
            # Get targets
            targets = self.get_targets()
            
            # Load and select templates
            template_engine = TemplateEngine()
            available_templates = template_engine.load_templates()
            
            if not available_templates:
                print(f"{Colors.RED}❌ No templates found!{Colors.END}")
                self.wait_for_user()
                return
            
            selected_templates = self.select_templates(available_templates)
            
            # Get enhanced scan settings
            concurrency, timeout, extract_data, cloud_scan, output_file = self.get_scan_settings()
            
            # Initialize enhanced scanner
            self.scanner = EnhancedVulnerabilityScanner(
                concurrency=concurrency, 
                timeout=timeout, 
                extract_data=extract_data,
                cloud_scan=cloud_scan
            )
            
            # Enhanced confirmation
            print(f"\n{Colors.BOLD}{Colors.YELLOW}🚀 ENHANCED SCAN SUMMARY{Colors.END}")
            print("=" * 60)
            print(f"{Colors.CYAN}Targets:{Colors.END} {len(targets)}")
            print(f"{Colors.CYAN}Templates:{Colors.END} {len(selected_templates)}")
            print(f"{Colors.CYAN}Concurrency:{Colors.END} {concurrency}")
            print(f"{Colors.CYAN}Timeout:{Colors.END} {timeout}s")
            print(f"{Colors.CYAN}Data Extraction:{Colors.END} {'Enabled' if extract_data else 'Disabled'}")
            print(f"{Colors.CYAN}Cloud Analysis:{Colors.END} {'Enabled' if cloud_scan else 'Disabled'}")
            if output_file:
                print(f"{Colors.CYAN}Output file:{Colors.END} {output_file}")
            
            confirm = input(f"\n{Colors.YELLOW}Start enhanced scanning? (y/N): {Colors.END}").strip().lower()
            if confirm not in ['y', 'yes']:
                print(f"{Colors.YELLOW}Scan cancelled.{Colors.END}")
                self.wait_for_user()
                return
            
            # Start enhanced scan
            print(f"\n{Colors.BOLD}{Colors.GREEN}🔍 ENHANCED SCANNING IN PROGRESS...{Colors.END}")
            if cloud_scan:
                print(f"{Colors.MAGENTA}☁️  Cloud analysis enabled{Colors.END}")
            if extract_data:
                print(f"{Colors.YELLOW}💾 Enhanced data extraction enabled{Colors.END}")
            print("=" * 70)
            
            results = asyncio.run(self.scanner.scan_multiple_targets(targets, selected_templates))
            
            # Enhanced results summary
            self._print_enhanced_summary(results, extract_data, cloud_scan)
            
            if output_file and results:
                self.save_enhanced_results(results, output_file)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.END}")
            self.wait_for_user()
        except Exception as e:
            print(f"\n{Colors.RED}❌ Error: {e}{Colors.END}")
            self.wait_for_user()

    def _print_enhanced_summary(self, results: List[ScanResult], extract_data: bool, cloud_scan: bool):
        """Print enhanced scan summary"""
        total_scans = len(results)
        successful_matches = len([r for r in results if r.matched])
        errors = len([r for r in results if r.error])
        extracted_files = len([r for r in results if r.extracted_file])
        cloud_services = len([r for r in results if r.cloud_metadata])
        
        print("=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}📊 ENHANCED SCAN COMPLETED{Colors.END}")
        print(f"{Colors.CYAN}Total requests:{Colors.END} {total_scans}")
        print(f"{Colors.GREEN}Successful matches:{Colors.END} {successful_matches}")
        print(f"{Colors.RED}Errors:{Colors.END} {errors}")
        
        if cloud_scan:
            print(f"{Colors.MAGENTA}☁️  Cloud services detected:{Colors.END} {cloud_services}")
        
        if extract_data:
            print(f"{Colors.YELLOW}💾 Files extracted:{Colors.END} {extracted_files}")
        
        # Enhanced findings summary
        if successful_matches > 0:
            print(f"\n{Colors.BOLD}📋 Findings by Severity:{Colors.END}")
            severity_count = {}
            for result in results:
                if result.matched:
                    severity_count[result.severity] = severity_count.get(result.severity, 0) + 1
            
            for severity, count in sorted(severity_count.items()):
                severity_colors = {
                    'info': Colors.BLUE,
                    'low': Colors.GREEN,
                    'medium': Colors.YELLOW,
                    'high': Colors.RED,
                    'critical': Colors.MAGENTA
                }
                color = severity_colors.get(severity, Colors.WHITE)
                print(f"  {color}{severity.upper()}: {count} findings{Colors.END}")
        
        self.wait_for_user()

    def save_enhanced_results(self, results: List[ScanResult], filename: str):
        """Save enhanced scan results"""
        output_data = []
        for result in results:
            result_dict = {
                'target': result.target,
                'template': result.template,
                'severity': result.severity,
                'matched': result.matched,
                'response_code': result.response_code,
                'response_time': result.response_time,
                'matched_text': result.matched_text,
                'error': result.error,
                'extracted_data': result.extracted_data,
                'extracted_file': result.extracted_file,
                'cloud_metadata': result.cloud_metadata,
                'ssl_info': result.ssl_info,
                'dns_info': result.dns_info,
                'match_detail': result.match_detail,
                'cloud_service': result.cloud_service
            }
            output_data.append(result_dict)
            
        try:
            with open(filename, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"{Colors.GREEN}✓ Enhanced results saved to {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}❌ Error saving results: {e}{Colors.END}")

    def show_main_menu(self) -> str:
        """Show enhanced main menu"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}🏠 ENHANCED MAIN MENU{Colors.END}")
        print("=" * 60)
        print(f"{Colors.GREEN}1.{Colors.END} Start Enhanced Security Scan")
        print(f"{Colors.GREEN}2.{Colors.END} Help & Usage Guide")
        print(f"{Colors.GREEN}3.{Colors.END} Exit")
        
        choice = input(f"\n{Colors.CYAN}Enter your choice (1-3): {Colors.END}").strip()
        return choice

    def run(self):
        """Enhanced main interactive loop"""
        self.print_banner()
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "1":
                    self.perform_scan()
                elif choice == "2":
                    self.show_help()
                    self.wait_for_user()
                elif choice == "3":
                    print(f"\n{Colors.GREEN}👋 Thanks for using the Enhanced Scanner! Goodbye!{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}❌ Invalid choice. Please try again.{Colors.END}")
                    self.wait_for_user()
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.END}")
                break
            except Exception as e:
                print(f"\n{Colors.RED}❌ Unexpected error: {e}{Colors.END}")
                self.wait_for_user()

def main():
    """Enhanced main entry point"""
    print(f"{Colors.YELLOW}Initializing Enhanced Nuclei-Inspired Scanner...{Colors.END}")
    
    # Check for required dependencies
    missing_deps = []
    if not DNS_AVAILABLE:
        missing_deps.append("dnspython")
    if not AWS_AVAILABLE:
        missing_deps.append("boto3")
    
    if missing_deps:
        print(f"{Colors.YELLOW}Warning: Some dependencies are missing: {', '.join(missing_deps)}{Colors.END}")
        print(f"{Colors.CYAN}Install with: pip install {' '.join(missing_deps)}{Colors.END}")
        print(f"{Colors.YELLOW}Some features may not work without these dependencies.{Colors.END}")
        time.sleep(2)
    
    scanner = InteractiveEnhancedScanner()
    scanner.run()

if __name__ == "__main__":
    main()
