import pytest
from typer.testing import CliRunner
from sentinel.main import app
import sentinel.main
from unittest.mock import patch, MagicMock

runner = CliRunner()

def test_scan_missing_headers():
    mock_response = MagicMock()
    mock_response.headers = {
        'Strict-Transport-Security': 'max-age=31536000'
    }
    
    # Ensure client is mocked so _explain_vulnerabilities is called
    with patch('requests.get', return_value=mock_response):
        with patch('sentinel.main.client', MagicMock()):
            with patch('sentinel.main._explain_vulnerabilities') as mock_explain:
                result = runner.invoke(app, ["scan", "example.com"])
                if result.exit_code != 0:
                    result = runner.invoke(app, ["example.com"])
                
                assert result.exit_code == 0
                assert "Strict-Transport-Security" in result.stdout
                assert "PRESENT" in result.stdout
                assert "Content-Security-Policy" in result.stdout
                assert "MISSING" in result.stdout
                mock_explain.assert_called_once()

def test_scan_error():
    with patch('requests.get', side_effect=Exception("Network failure")):
        result = runner.invoke(app, ["scan", "invalid-url"])
        if result.exit_code != 0:
            result = runner.invoke(app, ["invalid-url"])
            
        assert result.exit_code == 0
        assert "Error reaching target" in result.stdout
