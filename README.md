# CyberShield — Login Attack Detection Dashboard

A learning project built with Python, Streamlit, Pandas and Plotly. It analyzes fictional login events and highlights repeated failed logins.

## Features
- Login metrics and interactive charts
- Fictional sample data generation
- HIGH risk for 5+ failed attempts from the same IP in a rolling 5-minute window; MEDIUM for 3–4
- Login activity table, filters, security alerts and CSV download/upload

## Files
`app.py`, `generate_data.py`, `requirements.txt`, `data/login_logs.csv`, `tests/test_detection.py`, and `Cybershield Project.docx` (project report).

## Run locally
Python 3.10+ recommended. In a terminal opened in this folder run:
```bash
python -m pip install -r requirements.txt
python generate_data.py
streamlit run app.py
```
Open the local URL shown in the terminal (usually http://localhost:8501).

## Tests
Run `pytest -q`. Confirm results on your own computer before reporting them.

## CSV format
Required columns: `timestamp`, `username`, `ip_address`, `login_status` (`Success` or `Failed`).

## Limitations and safety
Uses fictional records and documentation-only IP ranges. It does not collect passwords, monitor live systems, or attack external hosts. Real monitoring requires authorized authentication-log integration, access controls, and rule tuning.

## Upload to GitHub
1. Create a repository named `cybershield-login-security-dashboard` on GitHub.
2. Upload the extracted files, or use Git commands:
```bash
git init
git add .
git commit -m "Add CyberShield dashboard"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/cybershield-login-security-dashboard.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your actual GitHub username. This is a template URL, not a published repository link.

## Before submission
Run the app, run tests, add genuine screenshots if requested, fill in your college/guide details in the report, and copy the real GitHub URL after uploading.
