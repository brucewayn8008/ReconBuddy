import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import aiohttp
from datetime import datetime

class BurpAutomation:
    def __init__(self, api_key: str, burp_url: str = "http://localhost:1337"):
        """
        Initialize Burp Suite automation module
        
        Args:
            api_key: Burp Suite API key
            burp_url: URL where Burp Suite API is running
        """
        self.burp_url = burp_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.logger = logging.getLogger("BurpAutomation")
        
    async def send_request(self, 
                          url: str, 
                          method: str = "GET",
                          headers: Dict[str, str] = None,
                          params: Dict[str, str] = None,
                          data: Any = None,
                          cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Send a request through Burp Suite
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers
            params: URL parameters
            data: Request body
            cookies: Request cookies
        """
        try:
            request_data = {
                "url": url,
                "method": method,
                "headers": headers or {},
                "params": params or {},
                "body": data,
                "cookies": cookies or {}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.burp_url}/v1/send_request",
                    headers=self.headers,
                    json=request_data
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            self.logger.error(f"Error sending request through Burp: {str(e)}")
            return {"error": str(e)}

    async def active_scan(self, 
                         url: str,
                         scan_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Start an active scan
        
        Args:
            url: Target URL
            scan_config: Scan configuration options
        """
        try:
            config = scan_config or {
                "scan_configurations": ["Lightweight scan"],
                "scope": {
                    "include": [{"rule": url}],
                    "exclude": []
                }
            }
            
            async with aiohttp.ClientSession() as session:
                # Start scan
                async with session.post(
                    f"{self.burp_url}/v1/scan",
                    headers=self.headers,
                    json={"url": url, "config": config}
                ) as response:
                    scan_id = (await response.json())["scan_id"]
                    
                # Poll for results
                while True:
                    async with session.get(
                        f"{self.burp_url}/v1/scan/{scan_id}",
                        headers=self.headers
                    ) as response:
                        status = await response.json()
                        if status["scan_status"] == "completed":
                            return status
                        await asyncio.sleep(10)
                        
        except Exception as e:
            self.logger.error(f"Error during active scan: {str(e)}")
            return {"error": str(e)}

    async def parameter_tampering(self,
                                url: str,
                                params: Dict[str, str],
                                payloads: List[str]) -> Dict[str, Any]:
        """
        Test parameter tampering
        
        Args:
            url: Target URL
            params: Original parameters
            payloads: List of payloads to test
        """
        results = []
        
        try:
            for param_name, param_value in params.items():
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = await self.send_request(
                        url=url,
                        params=test_params
                    )
                    
                    results.append({
                        "parameter": param_name,
                        "payload": payload,
                        "response": response
                    })
            
            return {"results": results}
            
        except Exception as e:
            self.logger.error(f"Error during parameter tampering: {str(e)}")
            return {"error": str(e)}

    async def replay_request(self,
                           request_file: str,
                           modifications: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Replay a saved request with optional modifications
        
        Args:
            request_file: Path to saved request file
            modifications: Changes to make to the request
        """
        try:
            with open(request_file) as f:
                request_data = json.load(f)
            
            if modifications:
                # Apply modifications to request
                for key, value in modifications.items():
                    if key in request_data:
                        request_data[key] = value
            
            return await self.send_request(**request_data)
            
        except Exception as e:
            self.logger.error(f"Error replaying request: {str(e)}")
            return {"error": str(e)}

if __name__ == "__main__":
    # Example usage
    async def main():
        burp = BurpAutomation(
            api_key="your_api_key_here",
            burp_url="http://localhost:1337"
        )
        
        # Example: Parameter tampering
        url = "http://example.com/api"
        params = {"id": "1", "user": "test"}
        payloads = ["'", "1 OR 1=1", "<script>alert(1)</script>"]
        
        results = await burp.parameter_tampering(url, params, payloads)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main()) 