# NetGuard release checklist

Work through this before the first public sale, then the "Every release" part each time.

## One-time setup

### 1. Protect the licence signing key
- `python tools/keygen.py init` already created `%USERPROFILE%\.netguard-signing\netguard_signing_key.pem`.
- **Back it up** to two offline places, for example an encrypted USB stick and a password manager.
  - If you lose it, you can't issue keys that existing installs accept.
  - If it leaks, anyone can make keys.
- Never put it in the project folder, on GitHub, or in an email. `.gitignore` already blocks `*.pem`.

### 2. Code-signing certificate
Without a certificate, Windows SmartScreen shows "Unknown publisher" and many buyers will stop there.

- **Standard (OV) certificate:** about $100–400 a year from Sectigo, DigiCert, SSL.com and others. Since 2023 these come on a hardware token or as a cloud signing service.
- **Azure Trusted Signing:** a low-cost cloud alternative if you qualify.
- To sign, set `NETGUARD_SIGN_CERT` and `NETGUARD_SIGN_PASS` before running `build.ps1`. For cloud signing, replace `Sign-File` in `build.ps1` with your provider's command.

### 3. Legal (needs a lawyer)
- [ ] Review and finalise `legal/EULA.txt`, especially the authorised-use clause, liability cap and governing law.
- [ ] Review and finalise `legal/PRIVACY.txt`, then fill in `[UPDATE URL]` and `[SUPPORT EMAIL]`.
- [ ] Fill in `[COMPANY NAME]` and `[JURISDICTION]`.
- [ ] Set `AppPublisher` in `packaging/installer.iss` and `CompanyName` in `packaging/version_info.txt`.

### 4. Website, payments and licence delivery
- [ ] A website with the product page, download link, EULA, privacy policy and support contact.
- [ ] A payment provider that acts as **merchant of record**, so it handles VAT and sales tax worldwide. Examples: Paddle, Lemon Squeezy, FastSpring.
- [ ] Licence delivery after each purchase:
  ```bash
  python tools/keygen.py issue --name "Customer Name" --email customer@example.com --days 365
  ```
  - **Start:** run the command by hand and email the key to the customer.
  - **Later:** run it from the payment provider's webhook on a small private server. Keep the private key on that server only.

### 5. Update checks
- Host a JSON file over HTTPS, for example on your website:
  `{"version": "3.0.1", "url": "https://your-site/download", "notes": "Bug fixes"}`
- Set `UPDATE_URL` in `scanner/updates.py` to its address.

## Every release
1. Bump the version in `scanner/__init__.py`, `packaging/version_info.txt` and `packaging/installer.iss`.
2. `powershell -ExecutionPolicy Bypass -File build.ps1`. This runs the tests, checks the licences, builds, signs and makes the installer.
3. Install `dist\NetGuard-Setup-<ver>.exe` on a clean Windows PC or VM. Check:
   - the first-run terms screen
   - a Quick Scan
   - a PDF report
   - trial and licence activation
   - the uninstaller
4. Upload the installer to the website, then update the JSON file from step 5.
5. Tag the release in Git: `git tag v3.0.0 && git push --tags`.
