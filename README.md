git clone https://github.com/aaminahhkhan/cybersecurity-incident-management

cd cybersecurity-incident-management
```

2. Install Python 3.11 or later if you haven't already:
   - Download from [Python.org](https://python.org/downloads/)
   - Make sure to check "Add Python to PATH" during installation

3. Install required packages:
```bash
pip install streamlit pandas plotly
```

4. Create a `.streamlit` directory and config file:
```bash
mkdir .streamlit
```

5. Create `.streamlit/config.toml` with these contents:
```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#0066cc"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
```

6. Run the application:
```bash
streamlit run main.py
```

The application will be available at `http://localhost:5000`

## Default Admin Account
- Username: admin
- Password: admin

## Project Structure
```
├── .streamlit/
│   └── config.toml      # Streamlit configuration
├── data/
│   ├── incidents.csv    # Incident records
│   └── users.csv        # User records
├── auth.py              # Authentication functions
├── database.py          # Database operations
├── main.py             # Main application
└── utils.py            # Utility functions
