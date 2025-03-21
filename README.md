# ReconBuddy

ReconBuddy is a comprehensive bug hunting automation tool that integrates multiple security tools for reconnaissance, vulnerability scanning, and reporting.

## Features

- Automated reconnaissance using ReconFTW integration
- Subdomain enumeration and analysis
- Port scanning and service detection
- Vulnerability scanning with Nuclei
- Centralized findings storage in PostgreSQL
- Detailed HTML and JSON reporting

## Prerequisites

- Python 3.8+
- PostgreSQL 12+
- ReconFTW and its dependencies
- Various security tools (listed below)

### Required Tools

- curl
- jq
- anew
- httpx
- nuclei
- amass
- subfinder
- assetfinder
- gobuster
- gau
- waybackurls
- katana
- hakrawler

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ReconBuddy.git
   cd ReconBuddy
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   .\venv\Scripts\activate  # Windows
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up PostgreSQL:
   ```bash
   # Create database
   createdb reconbuddy
   
   # Set environment variables
   export RECONBUDDY_DB_URL="postgresql://username:password@localhost:5432/reconbuddy"
   ```

5. Install required tools:
   ```bash
   # Install ReconFTW
   git clone https://github.com/six2dez/reconftw.git
   cd reconftw
   ./install.sh
   ```

## Configuration

1. Configure ReconFTW:
   - The tool will automatically create a default configuration if none exists
   - You can modify the configuration using the ReconFTWConfig class
   - API keys can be set via environment variables or the config file

2. Environment Variables:
   ```bash
   RECONBUDDY_DB_URL="postgresql://username:password@localhost:5432/reconbuddy"
   GITHUB_TOKEN="your_github_token"  # For GitHub-based recon
   ```

## Usage

1. Basic Usage:
   ```bash
   python ReconBuddy.py
   ```

2. Follow the interactive prompts:
   - Enter the target domain
   - Select scan type (Full, Passive, or Active)
   - Monitor progress in the terminal

3. Results:
   - Findings are stored in the PostgreSQL database
   - JSON and HTML reports are generated in the output directory
   - Logs are saved to recon.log

## Project Structure

```
ReconBuddy/
├── core/
│   ├── integration/
│   │   ├── reconftw_wrapper.py
│   │   ├── reconftw_config.py
│   │   └── reconftw_parser.py
│   └── db/
│       └── database.py
├── utils/
│   └── installer.py
├── ReconBuddy.py
├── requirements.txt
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- ReconFTW team for their excellent reconnaissance framework
- All the creators of the integrated security tools

## Security Considerations

- Always ensure you have proper authorization before scanning any target
- Follow responsible disclosure practices
- Keep your API keys secure
- Monitor system resource usage during scans

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## Roadmap

See the [PRD.md](PRD.md) file for detailed development phases and upcoming features.

---


