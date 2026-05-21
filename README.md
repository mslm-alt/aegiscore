**AegisCore**  
**AegisCore** is an alpha-stage Linux security monitoring and log analysis project.  
It focuses first on **rule-based detection**: reading Linux security logs, normalizing events, applying detection rules, and producing alerts for defensive monitoring. It also includes an  **experimental ML-assisted layer** designed to support per-system / per-user anomaly analysis and custom ML alert families. The ML layer is advisory and still under testing; it does not replace the rule-based engine and does not perform automatic enforcement.  
*Status: * ***Alpha / experimental***  
 *  
 Intended use: defensive monitoring, education, lab testing, and authorized internal Linux log analysis.*  
AegisCore must not be used to attack systems or monitor systems without authorization.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNBCUrfD6LYGNDAgAU2QtIq6DIzW7UHAMBfHGt1V+fXEwAAXrseHDAF/orRG+cAAAAASUVORK5CYII=)  
**What AegisCore Does**  
AegisCore is intended to help analyze Linux security activity such as:  
- SSH brute-force attempts and invalid-user enumeration  
- Suspicious authentication activity  
- Web attack patterns such as SQL injection, XSS, path traversal, and webshell-like requests  
- PostgreSQL login and suspicious database behavior  
- Firewall tampering attempts such as flush, disable, broad allow, or policy changes  
- DNS anomalies such as DGA-like or high-entropy queries  
- Process, package, service, auditd, log, and persistence-related behavior  
- Rule-backed label candidates and readiness information for experimental ML workflows  
The project is CLI-first, with an optional desktop UI for local operator use.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJe0PYTKpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseaIEEMYtKmi4AAAAASUVORK5CYII=)  
**Current Project Status**  
AegisCore is still being tested and refactored.  
The current stable focus is:  
- Rule-based detection  
- Log normalization  
- Alert generation  
- Safe/manual response workflows  
- CLI diagnostics and validation  
- PostgreSQL-backed persistence  
- Modularized runtime and ML helper architecture  
The experimental focus is:  
- ML readiness tracking  
- Rule-backed label candidates  
- Per-system / per-user anomaly-oriented alert families  
- Advisory ML scoring and reporting  
- Safe dry-run historical label workflows  
The ML layer should be treated as a supporting signal. It is not an automatic decision maker.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSeYxKS/kJkED6bwYAVvImwJtszMVu0BAPAXx1rd1fn1BACA164HHDwF+DpPyKwAAAAASUVORK5CYII=)  
**Safety Model**  
AegisCore is intentionally conservative.  
Important safety rules:  
- IP blocking is not automatic.  
- Firewall actions require guarded/manual flows.  
- ML does not override rule-based detection decisions.  
- The active ML decision layer is disabled by default.  
- ML output is advisory and experimental.  
- Destructive actions should require confirmation, audit, or dry-run controls.  
- Secrets, local logs, runtime state, model files, and database dumps must not be committed.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd40A5GMORPYEt7WMGbCFuCLTNzVFcAAPzFvVZbdX49AQDgtf0BSrIDUgOg4eAAAAAASUVORK5CYII=)  
**Supported Linux Families**  
| | |  
|-|-|  
| **Distribution Family** | **Examples** |   
| Debian family | Debian, Ubuntu |   
| RHEL family | RHEL, Rocky Linux, Fedora |   
| SUSE family | openSUSE, SUSE |   
   
AegisCore attempts to adapt log paths, parser behavior, and source settings based on the detected distribution family. Actual log paths may still vary by system configuration.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBACPiUML0NpGACyywEZJWQZeZ2aszAAD+4l6rrTq+ngAA8Nr1AL/SBEZwuCSwAAAAAElFTkSuQmCC)  
**Main Features**  
- Linux log reading and normalization  
- Rule-based detection engine  
- Threshold and correlation support  
- Alerts and incident-oriented workflows  
- PostgreSQL persistence  
- Manual IP block / unblock candidate workflows  
- Optional AbuseIPDB and OTX enrichment  
- Optional LLM-assisted alert explanation  
- Optional desktop operator UI  
- ML label readiness and phase tracking  
- Experimental per-system / per-user anomaly alert family support  
- Safe dry-run historical label candidate generation  
- Report and diagnostic commands  
- Secret redaction and guarded security controls  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNBCUrfD6LYGNDAgAU2QtIq6DIzW7UHAMBfHGt1V+fXEwAAXrseHDAF/orRG+cAAAAASUVORK5CYII=)  
**Project Layout**  
The current refactored structure is modular:  
AegisCore/  
 ├── main.py                    # CLI entrypoint and compatibility surface  
 ├── app/  
 │   ├── bootstrap.py  
 │   ├── configuration.py  
 │   ├── database_bootstrap.py  
 │   ├── startup.py  
 │   ├── alert_explanations.py  
 │   ├── runtime/               # SIEMPipeline runtime implementation and mixins  
 │   └── ml/                    # ML reporting, readiness, labels, training helpers  
 ├── cli/  
 │   ├── parser.py  
 │   ├── dispatcher.py  
 │   └── commands/  
 ├── core/  
 ├── ui/  
 ├── rules/  
 ├── scripts/  
 ├── packaging/  
 ├── config/  
 ├── data/labels/  
 ├── tests/  
 ├── requirements.txt  
 ├── pytest.ini  
 └── VERSION  
   
main.py is no longer the main implementation container. Most runtime, ML, CLI, startup, diagnostics, and explanation logic has been moved into app/, app/ml/, app/runtime/, and cli/.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OYQ1AABSAwc8mi5wvkwZyCKCAACr4Z7a7BLfMzFYdAQDwF+da3dX+9QQAgNeuB6feBdUJcyS2AAAAAElFTkSuQmCC)  
**Requirements**  
Basic requirements:  
- Linux system from a supported distribution family  
- Python 3.8+  
- PostgreSQL  
- pip and Python virtual environment support  
- Permission to read relevant system logs  
- Optional: PySide6 for the desktop UI  
- Optional: API keys for enrichment or LLM explanation integrations  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKa/i8WMIR7ECt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85PAYartXEogAAAABJRU5ErkJggg==)  
**Quick Start**  
**1. Create and activate a virtual environment**  
python3 -m venv .venv  
 .venv/bin/python -m pip install --upgrade pip  
 .venv/bin/python -m pip install -r requirements.txt  
   
**2. Configure PostgreSQL**  
Create a PostgreSQL user and database:  
sudo -u postgres createuser --pwprompt aegiscore  
 sudo -u postgres createdb --owner=aegiscore aegiscore  
   
Test the connection:  
psql "postgresql://aegiscore:YOUR_PASSWORD@localhost:5432/aegiscore" -c "select 1;"  
   
**3. Configure environment variables**  
Copy the safe example file:  
cp config/example.env .env  
   
Edit .env:  
DATABASE_URL=postgresql://aegiscore:YOUR_PASSWORD@localhost:5432/aegiscore  
   
Optional integration secrets should be kept in:  
cp config/integrations.example.env config/integrations.env  
   
Do not commit .env or config/integrations.env.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSfYxKK/kJXEkyE8WcGbCFuCLTOzVXsAAPzFsVZ3dX4cAQDgvesB/vEF9H9odtUAAAAASUVORK5CYII=)  
**Basic Verification**  
Validate rules:  
.venv/bin/python main.py --validate-rules  
   
Show help and version:  
.venv/bin/python main.py --help  
 .venv/bin/python main.py --version  
   
Run smoke test and status checks:  
.venv/bin/python main.py --smoke-test  
 .venv/bin/python main.py --status  
 .venv/bin/python main.py --phase  
 .venv/bin/python main.py --ml-summary  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJe0PYTKpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseaIEEMYtKmi4AAAAASUVORK5CYII=)  
**Running the Backend**  
Manual backend run:  
sudo -E .venv/bin/python main.py  
   
Run with a specific config file:  
sudo -E .venv/bin/python main.py --config config/config.yml  
   
sudo -E may be required when the backend needs permission to read /var/log/* while preserving environment variables such as DATABASE_URL.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OUQmAABBAsSeYxZyXSzCJASxgACv4J8KWYMvMbNURAAB/ca7VXe1fTwAAeO16AKe+BdmJqrPdAAAAAElFTkSuQmCC)  
**Optional Desktop UI**  
The desktop UI is optional and intended for local operator visibility.  
Install/check PySide6 if needed:  
.venv/bin/python -m pip show PySide6  
 .venv/bin/python -m pip install PySide6  
   
Start the UI:  
.venv/bin/python -m ui.app  
   
If the UI opens but no data appears, verify that the backend and UI use the same database and configuration.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsad4FCtY9ecwnkms4E2ELcGWmTmrKwAA/uLeqrU6vp4AAPDa/gDzUgM9+S8z3AAAAABJRU5ErkJggg==)  
**Useful Commands**  
**Rule and Health Checks**  
.venv/bin/python main.py --validate-rules  
 .venv/bin/python main.py --smoke-test  
 .venv/bin/python main.py --status  
 .venv/bin/python main.py --phase  
 .venv/bin/python main.py --ml-summary  
   
**Database Checks**  
.venv/bin/python main.py --db-version  
 .venv/bin/python main.py --db-pending  
 .venv/bin/python main.py --db-doctor  
   
**Historical Label / ML Readiness Workflows**  
.venv/bin/python main.py --ml-historical-scan-plan  
 .venv/bin/python main.py --bootstrap-label-scan --dry-run  
 .venv/bin/python main.py --ml-readiness  
 .venv/bin/python main.py --ml-summary  
   
These commands are intended for safe inspection and dry-run workflows. They do not automatically enable active ML decisions or automatic response actions.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSPBCj7fFRYQwYwEZiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AMTJBeJDClAyAAAAAElFTkSuQmCC)  
**ML Layer**  
AegisCore includes an experimental ML-assisted layer. Its goal is not to replace deterministic rules. Instead, it supports:  
- rule-backed label preparation  
- readiness and phase tracking  
- historical dry-run label candidate generation  
- custom anomaly-oriented alert family experiments  
- per-system / per-user behavioral analysis support  
Default safe expectations:  
- ML is advisory.  
- ML does not automatically block IPs.  
- ML does not override rule-based alerts.  
- Active ML behavior should remain disabled unless explicitly configured and validated.  
- Training should only be considered when readiness, metadata, and safety gates are satisfied.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OUQmAABBAsSeIWMICprwEpjSIFfwTYUuwZWaO6goAgL+412qrzq8nAAC8tj8tdQNNdXaCdAAAAABJRU5ErkJggg==)  
**Log Sources**  
AegisCore can read different log sources depending on distro and configuration.  
Typical sources include:  
| | |  
|-|-|  
| **Source** | **Common Paths** |   
| Auth / SSH | /var/log/auth.log, /var/log/secure, journald |   
| Syslog / Messages | /var/log/syslog, /var/log/messages |   
| Audit | /var/log/audit/audit.log |   
| PostgreSQL | /var/log/postgresql, /var/lib/pgsql/data/log |   
| Web | /var/log/nginx, /var/log/apache2, /var/log/httpd |   
   
If your system uses different paths, update config/config.yml.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/jkUsYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4rDBc72meO5AAAAAElFTkSuQmCC)  
**Optional Integrations**  
Optional integrations are configured locally and must not be committed:  
ABUSEIPDB_API_KEY=put_your_abuseipdb_api_key_here  
 OTX_API_KEY=put_your_otx_api_key_here  
 GEMINI_API_KEY=put_your_gemini_api_key_here  
 OPENAI_API_KEY=put_your_openai_api_key_here  
 ANTHROPIC_API_KEY=put_your_anthropic_api_key_here  
   
LLM explanations and enrichment sources are operator-assistance features only. They should not trigger automatic security actions.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNBCUrfDqrYGVDAgAU2QtIq6DIzW7UHAMBfHGt1V+fXEwAAXrseHCQGBEuErVgAAAAASUVORK5CYII=)  
**Testing**  
Run targeted validation:  
.venv/bin/python -m py_compile main.py app/*.py app/ml/*.py app/runtime/*.py cli/parser.py cli/dispatcher.py cli/commands/*.py  
 .venv/bin/python -m pytest tests/unit -q  
   
UI tests require PySide6:  
.venv/bin/python -m pytest tests/ui -q  
   
If PySide6 is not installed, UI test collection may fail even when backend tests are healthy.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OsQ1AABRAwSdRaPXGMOCv7WkPK+hEcjfBLTNzVFcAAPzFvVZbdX49AQDgtf0BSpoDXv5TGXgAAAAASUVORK5CYII=)  
**Packaging / Release Hygiene**  
A clean public package should include source code and safe examples only.  
Allowed examples:  
config/example.env  
 config/integrations.example.env  
 data/labels/  
   
Do not include:  
.env  
 .env.*  
 config/integrations.env  
 data/*.log  
 data/models/  
 data/runtime_state*  
 data/exports/  
 data/diagnostic_bundles/  
 data/bootstrap_label_scan/  
 .venv/  
 venv/  
 __pycache__/  
 .pytest_cache/  
 dist/  
 release_staging/  
 temp_verify/  
 *.sqlite  
 *.db  
 *.dump  
 *.sql  
 *.pem  
 *.key  
 *.crt  
   
The packaging process should verify that app/runtime/ is included, because it contains source code, not runtime artifacts.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OYQ1AABSAwY9JoICqL4Z8Ikiggn9mu0twy8wc1RkAAH9xbdVa7V9PAAB47X4A9CgEJQFjJ/EAAAAASUVORK5CYII=)  
**Development Note**  
AegisCore was developed as a university graduation project with AI-assisted coding support. AI tools were used mainly to speed up implementation and refactoring. Project direction, architecture decisions, safety boundaries, review, acceptance/rejection decisions, and testing priorities remained under the maintainer's control.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJGkPcrHpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseaJkELjbMzy0AAAAASUVORK5CYII=)  
**Intended Use**  
AegisCore is intended for:  
- defensive monitoring  
- education  
- controlled lab testing  
- internal security research  
- authorized Linux log analysis  
Use it only on systems that you own or are explicitly authorized to monitor.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/jzlMYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4q7Bc870TqdAAAAAElFTkSuQmCC)  
**License**  
**## License**  
   
**This project is licensed under the **Apache License 2.0**.**  
   
**See the [`LICENSE`](LICENSE) file in the project root for details.**  
