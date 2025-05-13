# 🕵️ CMS Detector

**CMS Detector** is a lightweight Python tool designed to detect both *self-hosted* and *headless/SaaS* CMS platforms by analyzing known API endpoints and the web page’s source code. This tool is part of the \[**mgt0ls**] cybersecurity project and is intended for OSINT, penetration testing, and web auditing tasks.

> 🎯 Ideal for identifying exposed or misconfigured CMS technologies.

---

## 🚀 Features

* ✅ Detects self-hosted CMS platforms like WordPress, Joomla, Drupal, etc.
* 🌐 Identifies SaaS/headless CMS like Prismic, Contentful, and more.
* 🔍 Supports shallow and deep API scanning.
* 💡 Based on real-world endpoint patterns.
* 🧵 Uses multithreading via `ThreadPoolExecutor` for fast scanning.

---

## 🧠 How It Works

* Analyzes the site's HTML code for SaaS CMS references.
* Scans known public API paths (`/wp-json`, `/ghost/api`, etc.).
* Validates responses against a CMS signature database.
* When `--deep` mode is enabled, performs a second pass with hidden/less common endpoints.
* Saves all detected endpoints and CMS findings in `save_report.txt`.

---

## 📦 Installation

```bash
git clone https://github.com/ciberuniverse/CMS_Detector.git
cd CMS_Detector
```

> ⚠️ Requires a `web_control.json` file containing CMS signatures and endpoint structures.

---

## 🛠️ Usage

```bash
python3 CMS_Detector.py
```

Input example:

```
:: CMS DETECTOR =>> MIT LICENSE ::
> EX4MPL3: https://target.website.com --deep

W3B-URL-T0-SC4N =>> https://target.website.com --deep
```

> Use `--deep` to trigger a deeper endpoint scan.

---

## 📄 Output

Results are saved automatically to:

```
save_report.txt
```

Includes:

* Detected CMS names
* Discovered API endpoints
* Documentation references for each CMS

---
## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## ✨ Credits

Developed by \[Hernán Miranda] as part of the **mgt0ls** project 🧪
Inspired by real-world reconnaissance scenarios and OSINT research.

## 📬 Contact

Feel free to connect or reach out via [LinkedIn](https://www.linkedin.com/in/hernan-mirand4).