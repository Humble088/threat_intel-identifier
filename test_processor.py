import pytest
from threat_intel_processor import OTXFeed, AbuseIPDBFeed, IOCProcessor
from unittest.mock import patch, MagicMock
import configparser

@pytest.fixture
def mock_config():
    config = configparser.ConfigParser()
    config['API_KEYS'] = {
        'otx_key': 'test_key',
        'abuseipdb_key': 'test_key',
        'virustotal_key': 'test_key'
    }
    config['ELASTICSEARCH'] = {
        'host': 'localhost',
        'port': '9200',
        'index': 'test_index',
        'log_index': 'test_logs'
    }
    config['SETTINGS'] = {
        'fetch_interval': '3600',
        'max_iocs': '1000'
    }
    return config

def test_otx_feed_fetch(mock_config):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'results': [{
                'id': '123',
                'name': 'Test Pulse',
                'indicators': [{
                    'indicator': '1.1.1.1',
                    'type': 'IPv4',
                    'created': '2023-01-01T00:00:00'
                }]
            }]
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        feed = OTXFeed(mock_config['API_KEYS']['otx_key'])
        iocs = feed.fetch_iocs()
        
        assert len(iocs) > 0
        assert iocs[0]['value'] == '1.1.1.1'

def test_ioc_processor_init(mock_config):
    processor = IOCProcessor()
    processor.config = mock_config
    assert len(processor.feeds) > 0

@patch('elasticsearch.Elasticsearch')
def test_es_connection(mock_es, mock_config):
    mock_es.return_value.ping.return_value = True
    processor = IOCProcessor()
    processor.config = mock_config
    processor._initialize_elasticsearch()
    assert processor.es is not None

def test_ioc_standardization():
    test_ioc = {
        'value': 'malicious-domain.com',
        'type': 'domain',
        'first_seen': '2023-01-01',
        'source': 'test'
    }
    standardized = OTXFeed.standardize_ioc(test_ioc)
    assert 'confidence' in standardized
    assert standardized['type'] == 'domain'