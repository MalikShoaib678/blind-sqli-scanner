


<h1 align="center">Blind SQLi Scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Python-3.6%2B-blue.svg" alt="Python Version">
</p>

<p align="center">
  <strong>A powerful tool for detecting Blind SQL Injection vulnerabilities</strong>
</p>

## 📖 Introduction

Blind SQLi Scanner is a Python-based tool designed to detect Blind SQL Injection vulnerabilities in web applications. It utilizes various techniques to analyze and test target URLs for potential vulnerabilities, providing valuable insights and results.

## 🚀 Features

- Detection of Blind SQL Injection vulnerabilities in web applications
- Multi-threaded scanning for efficient and fast testing
- Support for both GET and POST methods
- Customizable output options and verbosity levels
- Proxy support for testing through proxies

## 🛠️ Installation

1. Clone the repository:

   ```bash
   https://github.com/MalikShoaib678/blind-sqli-scanner.git
   ```

2. Navigate to the tool's directory:

   ````bash
   cd blind-sqli-scanner
   ```

3. Install the required libraries:

   ````bash
   pip install -r requirements.txt
   ```

4. Run the tool with the desired options (see the Usage section).

## ⚙️ Usage

To use the Blind SQLi Scanner, follow the steps below:

1. Provide the target URL or a list of URLs:

   ````bash
   python3 blind-sqli.py -u <URL>                       # Single URL
   python3 blind-sqli.py -l <path_to_list_file.txt>      # List of URLs
   ```

2. Customize the scanning options as needed:

   - Specify the number of URL threads:

     ```bash
     python3 blind-sqli.py -ut <num_threads>
     ```

   - Specify the number of payload threads:

     ```bash
     python3 blind-sqli.py -pt <num_threads>
     ```

   - Enable crawling for target URLs:

     ```bash
     python3 blind-sqli.py --crawl True
     ```

   - Provide a file containing custom payloads:

     ```bash
     python3 blind-sqli.py -p <path_to_payloads_file.txt>
     ```

   - Specify an output file for the results:

     ```bash
     python3 blind-sqli.py -o <output_file_name.txt>
     ```

   - Provide a file containing custom patterns to match:

     ```bash
     python3 blind-sqli.py -ptf <path_to_patterns_file.txt>
     ```

   - Provide a file containing a list of parameters to test only:

     ```bash
     python3 blind-sqli.py -pf <path_to_parameters_file.txt>
     ```

   - Set a proxy URL (optional):

     ```bash
     python3 blind-sqli.py --proxy <proxy_url>
     ```

   - Specify the scan mode (1: GET method, 2: POST method, 3: GET & POST method):

     ```bash
     python3 blind-sqli.py -m <scan_mode>
     ```

   - Set the verbosity level (1, 2, or 3):

     ```bash
     python3 blind-sqli.py -v <verbosity_level>
     ```

   - Set the field visibility (2: hidden & text fields, 3: all fields except hidden, 4: all fields):

     ```bash
     python3 blind-sqli.py --hidden <field_visibility>
     ```

   - Specify the attack technique (1: Sniper attack, 2: Battering Ram attack):

     ```bash
     python3 blind-sqli.py -t <attack_technique>
     ```

3. Execute the command to start the scan.



## ❤️ Contributing

Contributions to the Blind SQLi Scanner are welcome! If you find any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue.

## 📞 Contact

For any questions or inquiries, please contact [shoaib688malik@gmail.com](mailto:shoaib688malik@gmail.com).

---

Enjoy scanning for Blind SQL Injection vulnerabilities with the Blind SQLi Scanner! 🎯🔍
```


