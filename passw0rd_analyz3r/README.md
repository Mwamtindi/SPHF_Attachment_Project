# Password Strength Analyzer

This is a GUI-based **Password Strength Analyzer** built with Python and Tkinter. The application allows users to:

- Check password strength based on various security criteria.
- Generate strong, random passwords.
- Copy the generated password to the clipboard.
- Check if a password has been compromised using the **Have I Been Pwned** API.

## Prerequisites

Before running the project, ensure you have the following installed:

### 1. Install Python (Version 3.6 or later)
- Download and install Python from [python.org](https://www.python.org/downloads/).
- Verify installation by running:
  ```sh
  python --version
  ```

### 2. Install Required Python Packages
This project requires the following Python libraries:
- `tkinter` (Comes pre-installed with Python)
- `requests` (For API requests)
- `secrets` (For secure password generation)
- `hashlib` (For hashing passwords)

You can install the dependencies using pip:
```sh
pip install requests
```

## Cloning the Repository
To get started, clone the repository from GitHub:
```sh
git clone https://github.com/Mwamtindi/SPHF_Attachment_Project.git
cd password_analyz3r
```

## Activate Virtual Environment
The repository already contains a virtual environment (`password_analyzer_env`) with all required dependencies. Activate it using the appropriate command for your OS:

#### Windows (Command Prompt or PowerShell):
```sh
password_analyzer_env\Scripts\activate
```

#### macOS/Linux (Terminal):
```sh
source password_analyzer_env/bin/activate
```

## Running the Application
Once inside the project folder, run the following command:
```sh
python passwd_ch3ck3r.py
```

This will launch the graphical user interface (GUI).

## Deactivating Virtual Environment
After running the application, you can deactivate the virtual environment by running:
```sh
deactivate
```

## Features
- **Password Strength Meter:** Displays the security level of a password.
- **Password Generator:** Generates strong passwords automatically.
- **Copy to Clipboard:** Allows users to copy generated passwords.
- **Have I Been Pwned API:** Checks if a password has been compromised.
- **Show/Hide Password:** Users can toggle password visibility.

## Troubleshooting
If you encounter SSL errors while checking breached passwords, install or update `certifi`:
```sh
pip install --upgrade certifi
```
Then, modify the API request line in `passwd_ch3rk3r.py`:
```python
import certifi
requests.get(url, verify=certifi.where())
```

## License
This project is open-source.

## Author
Developed by [Shabani Mwamtindi](https://github.com/Mwamtindi)
