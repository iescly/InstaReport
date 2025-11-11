import os
import sys
import json
import base64
import hashlib
import platform
import subprocess
import argparse
import time
from datetime import datetime, timedelta
import uuid

# Check for required modules
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import psutil
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Please install required packages:")
    print("pip install -r requirements.txt")
    print("or")
    print("pip install selenium psutil cryptography")
    input("Press Enter to exit...")
    sys.exit(1)

# ==================== BASIC PROTECTION ====================

def _check_debug():
    """Basic anti-debugging check"""
    try:
        debugger_processes = ['gdb', 'strace', 'ltrace', 'ida', 'ollydbg', 'x64dbg']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() in debugger_processes:
                print("Debugging detected. Exiting...")
                sys.exit(1)
    except:
        pass

def _integrity_check():
    """Basic integrity check"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        expected_files = ['owner.key', 'acc.txt']
        for file in expected_files:
            if not os.path.exists(os.path.join(current_dir, file)):
                pass  # Continue anyway
    except:
        pass

# Initialize basic protection
# _check_debug()
# _integrity_check()

# ==================== LICENSE VALIDATION SYSTEM ====================

class LicenseSystem:
    def __init__(self):
        # Encoded keys for basic protection
        self.owner_bypass_key = base64.b64decode(b'T1dORVJfTUFTVEVSXzIwMjRfSU5TVEFSRVBPUlQ=').decode()
        self.license_codes_file = "valid_codes.dat"
        self.key_salt = b'instareport_salt_2024_v2'
        
    def check_owner_bypass(self):
        """Check if owner bypass is activated"""
        try:
            if os.path.exists("owner.key"):
                with open("owner.key", "r") as f:
                    key = f.read().strip()
                    if key == self.owner_bypass_key:
                        return True
            if os.environ.get("INSTAREPORT_OWNER") == self.owner_bypass_key:
                return True
            return False
        except:
            return False
    
    def show_owner_login(self):
        """Show owner login interface"""
        print("\n" + "="*60)
        print("         INSTAREPORT - OWNER ACCESS")
        print("="*60)
        print("Enter owner master key to bypass license validation")
        print("(Leave empty to continue with public license validation)")
        print("-"*60)
        
        owner_key = input("Owner Master Key: ").strip()
        
        if owner_key == self.owner_bypass_key:
            with open("owner.key", "w") as f:
                f.write(self.owner_bypass_key)
            print("✅ Owner access granted! Bypass activated.")
            return True
        elif owner_key == "":
            return False
        else:
            print("❌ Invalid owner key!")
            return False
    
    def generate_key(self, password):
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.key_salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def load_valid_codes(self):
        """Load valid license codes from encrypted file"""
        try:
            if not os.path.exists(self.license_codes_file):
                return []
            
            with open(self.license_codes_file, 'rb') as f:
                encrypted_data = f.read()
            
            key = self.generate_key(self.owner_bypass_key)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data).decode()
            
            codes_data = json.loads(decrypted_data)
            return codes_data.get('codes', [])
        except:
            return []
    
    def validate_license_code(self, code):
        """Validate entered license code"""
        valid_codes = self.load_valid_codes()
        
        for code_entry in valid_codes:
            if code_entry['code'] == code:
                if 'expiry' in code_entry:
                    expiry_date = datetime.fromisoformat(code_entry['expiry'])
                    if datetime.now() > expiry_date:
                        return False, "License code expired"
                
                if 'uses_left' in code_entry and code_entry['uses_left'] <= 0:
                    return False, "License code usage limit reached"
                
                return True, "Valid license code"
        
        return False, "Invalid license code"
    
    def show_payment_interface(self):
        """Show payment interface for users without license"""
        print("\n" + "="*70)
        print("         🔒 INSTAREPORT - LICENSE REQUIRED 🔒")
        print("="*70)
        print("This software requires a valid license to run.")
        print("You can purchase a license or enter an existing license code.")
        print()
        print("💰 PRICING:")
        print("   • 30 Days License: $29.99")
        print("   • 90 Days License: $79.99") 
        print("   • 1 Year License: $199.99")
        print("   • Lifetime License: $499.99")
        print()
        print("💳 PAYMENT METHODS:")
        print("   • upi: 9707905478")
        print("   • Crypto (USDT BSC bep20): 0xd1e005178b87cee6a815cf595ac98c1e9b93402e")
        print("   • Bank Transfer: Contact for details")
        print()
        print("📧 CONTACT FOR PURCHASE:")
        print("   • Email: nhackerraj@gmail.com")
        print("   • Telegram: @iEscly")
        print("   • instagram: @i3scly")
        print()
        print("🎫 ALREADY HAVE A LICENSE CODE?")
        print("   Enter it below to activate your license.")
        print("="*70)
        
        while True:
            print("\nOptions:")
            print("1. Enter license code")
            print("2. Purchase license (opens payment info)")
            print("3. Exit")
            
            choice = input("\nSelect option (1-3): ").strip()
            
            if choice == "1":
                code = input("Enter your license code: ").strip().upper()
                if code:
                    valid, message = self.validate_license_code(code)
                    if valid:
                        print(f"✅ {message}")
                        with open("user_license.txt", "w") as f:
                            f.write(code)
                        return True
                    else:
                        print(f"❌ {message}")
                        print("Please check your code or contact support.")
                else:
                    print("Please enter a valid code.")
            
            elif choice == "2":
                self.show_purchase_details()
                
            elif choice == "3":
                return False
            
            else:
                print("Invalid choice. Please select 1-3.")
    
    def show_purchase_details(self):
        """Show detailed purchase information"""
        print("\n" + "="*70)
        print("         💳 PURCHASE INSTAREPORT LICENSE")
        print("="*70)
        print("STEP 1: Choose your license duration")
        print("STEP 2: Make payment using one of the methods below")
        print("STEP 3: Send payment proof")
        print("STEP 4: Receive your license code within 24 hours")
        print()
        print("💰 PAYMENT DETAILS:")
        print("-"*40)
        print("UPI: 9365593766@omni")
        print("USDT (BEP20): 0xb14efbbb184efd0b971f0ff2672d452d9f9fa3aa")
        print("Bitcoin: 3BbHenasptSireuNMbxQ7nofchPFFXhWtr")
        print("Ethereum: 0xb14efbbb184efd0b971f0ff2672d452d9f9fa3aa")
        print()
        print("📧 SEND PAYMENT PROOF TO:")
        print("-"*40)
        print("TeleGram: @iEscly")
        print("instaGram: @i3scly")
        print("Subject: License Purchase - [Your Name]")
        print("Include:")
        print("  • Payment screenshot/transaction ID")
        print("  • License duration purchased")
        print()
        print("⚡ FAST TRACK (Additional $5):")
        print("Get your license within 2 hours instead of 24 hours")
        print()
        print("🔄 REFUND POLICY:")
        print("30-day money back guarantee if not satisfied")
        print("="*70)
        
        input("\nPress Enter to return to main menu...")
    
    def check_saved_license(self):
        """Check if user has a saved license code"""
        try:
            if os.path.exists("user_license.txt"):
                with open("user_license.txt", "r") as f:
                    code = f.read().strip()
                    if code:
                        valid, message = self.validate_license_code(code)
                        if valid:
                            return True
                        else:
                            os.remove("user_license.txt")
            return False
        except:
            return False
    
    def check_license(self):
        """Main license check function"""
        if self.check_owner_bypass():
            print("🔓 Owner access detected - bypassing license validation")
            return True
        
        if self.show_owner_login():
            return True
        
        if self.check_saved_license():
            print("✅ Valid license found")
            return True
        
        if self.show_payment_interface():
            return True
        
        print("\n❌ No valid license found. Exiting...")
        sys.exit(1)

# ==================== APPLICATION COMPONENTS ====================

def show_banner():
    """Display application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                      INSTAREPORT - LICENSED                  ║
    ║                    Mass Instagram Reporter                   ║
    ║                                                              ║
    ║                    🔒 PROTECTED VERSION 🔒                   ║
    ║                                                              ║
    ║              This software is license protected              ║
    ║                 Unauthorized use prohibited                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print("License Status: ✅ VALID")
    print("-" * 66)

def show_loading_screen(duration):
    """Display loading animation"""
    chars = "|/-\\"
    for i in range(duration * 4):
        sys.stdout.write(f'\rLoading {chars[i % len(chars)]} ')
        sys.stdout.flush()
        time.sleep(0.25)
    
    sys.stdout.write('\rLoading complete!   \n')
    sys.stdout.flush()

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ["selenium", "psutil", "cryptography"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nPlease install missing packages using:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True

def debug_page_structure(driver):
    """Debug function to see what's on the page"""
    try:
        from selenium.webdriver.common.by import By
        
        # Get all input fields
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"🔍 Found {len(inputs)} input fields on page:")
        for i, input_field in enumerate(inputs):
            input_type = input_field.get_attribute("type")
            input_name = input_field.get_attribute("name")
            input_placeholder = input_field.get_attribute("placeholder")
            input_aria_label = input_field.get_attribute("aria-label")
            print(f"  {i+1}. Type: {input_type}, Name: {input_name}, Placeholder: {input_placeholder}, Aria-label: {input_aria_label}")
        
        # Get all buttons
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"🔍 Found {len(buttons)} buttons on page:")
        for i, button in enumerate(buttons):
            text = button.text.strip()
            button_type = button.get_attribute("type")
            if text or button_type:
                print(f"  {i+1}. Button: '{text}', Type: {button_type}")
        
        # Get page title and URL
        print(f"🌐 Current URL: {driver.current_url}")
        print(f"📄 Page title: {driver.title}")
        
    except Exception as e:
        print(f"❌ Debug error: {e}")

def find_and_click_element(driver, selectors, timeout=10, element_name="element"):
    """Try multiple selectors to find and click an element"""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    
    for selector in selectors:
        try:
            element = WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((By.XPATH, selector))
            )
            element.click()
            print(f"✅ Found {element_name} with selector: {selector}")
            return True
        except Exception as e:
            continue
    print(f"❌ Could not find {element_name} with any selector")
    return False

def find_and_send_keys(driver, selectors, keys, timeout=10, element_name="element"):
    """Try multiple selectors to find and send keys to an element"""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    
    for selector in selectors:
        try:
            element = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.XPATH, selector))
            )
            element.clear()
            element.send_keys(keys)
            print(f"✅ Found {element_name} with selector: {selector}")
            return True
        except Exception as e:
            continue
    print(f"❌ Could not find {element_name} with any selector")
    return False

def wait_for_login_completion(driver, account_username, timeout=60):
    """Wait for login to complete, handling OTP and 2FA"""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException
    
    print("⏳ Waiting for login to complete...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        current_url = driver.current_url
        
        # Check if we're on the home page (login successful)
        if "instagram.com" in current_url and ("/accounts/login" not in current_url and "login" not in current_url):
            try:
                # Look for home page elements to confirm login
                home_indicators = [
                    "//a[contains(@href, '/direct/inbox/')]",
                    "//a[contains(@href, '/explore/')]",
                    "//a[contains(@href, '/reels/')]",
                    "//span[contains(text(), 'Home')]",
                    "//div[contains(@class, 'home')]"
                ]
                
                for indicator in home_indicators:
                    try:
                        element = driver.find_element(By.XPATH, indicator)
                        if element.is_displayed():
                            print("✅ Login successful - reached home page")
                            return True
                    except:
                        continue
                
                # If we're not on login page and no errors, assume success
                print("✅ Login likely successful")
                return True
                
            except Exception as e:
                print(f"⚠️  Checking login status: {e}")
                continue
        
        # Check for OTP/2FA requirement
        try:
            otp_elements = driver.find_elements(By.XPATH, "//input[@placeholder='Security code'] | //input[contains(@aria-label, 'code')] | //input[contains(@name, 'code')] | //h2[contains(text(), 'Code')]")
            if otp_elements:
                print("🔐 OTP/2FA detected - manual intervention required")
                print("💡 Please complete the security verification manually")
                input("Press Enter after completing OTP/2FA verification...")
                # Wait a bit after manual intervention
                time.sleep(5)
                continue
        except:
            pass
        
        # Check for "Suspicious Login Attempt" or other security challenges
        try:
            security_challenge = driver.find_elements(By.XPATH, "//h2[contains(text(), 'Suspicious')] | //h2[contains(text(), 'Challenge')] | //button[contains(text(), 'This Was Me')]")
            if security_challenge:
                print("⚠️  Security challenge detected - manual intervention required")
                print("💡 Please complete the security challenge manually")
                input("Press Enter after completing security challenge...")
                time.sleep(5)
                continue
        except:
            pass
        
        # Check for login errors
        try:
            error_messages = driver.find_elements(By.XPATH, "//*[contains(text(), 'incorrect')] | //*[contains(text(), 'error')] | //*[contains(text(), 'problem')] | //*[contains(text(), 'invalid')]")
            if error_messages:
                for error in error_messages:
                    if error.is_displayed():
                        print(f"❌ Login error: {error.text}")
                        return False
        except:
            pass
        
        # Check if we're still on login page after a while
        if "accounts/login" in current_url and time.time() - start_time > 15:
            print("❌ Still on login page after 15 seconds - login likely failed")
            return False
        
        time.sleep(2)
    
    print("❌ Login timeout reached")
    return False

def report_accounts(username, accounts_file):
    """Main reporting function - WITH PROPER LOGIN HANDLING"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.common.keys import Keys
    except ImportError:
        print("❌ Selenium not installed. Please run: pip install selenium")
        return
    
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    options.add_argument("--window-size=1920,1080")

    # Read account credentials from file
    try:
        with open(accounts_file, "r") as file:
            accounts = [line.strip().split(":") for line in file if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"Error: Account file '{accounts_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading account file: {str(e)}")
        return

    if not accounts:
        print("No accounts found in the file.")
        return

    # Initialize WebDriver
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        print(f"Initialized WebDriver successfully. Processing {len(accounts)} accounts...")
    except WebDriverException as e:
        print("Error: WebDriver initialization failed.")
        print("Make sure ChromeDriver is installed and in PATH.")
        print(f"Details: {e}")
        return

    successful_reports = 0
    failed_reports = 0

    # Iterate through accounts
    for i, account in enumerate(accounts, 1):
        if len(account) < 2:
            print(f"Skipping invalid account format: {account}")
            failed_reports += 1
            continue
            
        print(f"\nProcessing account {i}/{len(accounts)}: {account[0]}")
        
        try:
            # Periodic security check
            if i % 3 == 0:
                _check_debug()
            
            # Log in - COMPLETELY UPDATED LOGIN PROCESS
            print("🌐 Navigating to Instagram login...")
            driver.get("https://www.instagram.com/accounts/login/")
            time.sleep(3)
            
            # Wait for page to load completely
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # DEBUG: Show page structure
            print("🔍 Debugging page structure...")
            debug_page_structure(driver)
            
            # UPDATED: Try to find username/email field with CURRENT selectors
            username_selectors = [
                "//input[@name='username']",
                "//input[@aria-label='Phone number, username, or email']",
                "//input[@aria-label='Username']",
                "//input[@placeholder='Phone number, username, or email']",
                "//input[@placeholder='Username']",
                "//input[@type='text']",
                "//input[contains(@class, 'input')]",
                "//input[@id='loginForm']//input[@type='text']",
                "//form//input[@type='text']",
                "//input[@name='email']",
                "//input[@aria-label='Email']",
                "//input[@placeholder='Email']",
                "//input[1]",  # First input on page
                "//input",  # Any input field
            ]
            
            # Try each selector with longer timeout
            username_found = False
            username_field = None
            for selector in username_selectors:
                try:
                    print(f"🔍 Trying username selector: {selector}")
                    username_field = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, selector))
                    )
                    if username_field.is_displayed() and username_field.is_enabled():
                        username_field.clear()
                        username_field.send_keys(account[0])
                        print(f"✅ Username field found with: {selector}")
                        username_found = True
                        break
                except:
                    continue
            
            if not username_found:
                print("❌ Could not find username field")
                # Try to find any visible input and click it
                try:
                    inputs = driver.find_elements(By.TAG_NAME, "input")
                    for input_field in inputs:
                        if input_field.is_displayed():
                            input_field.click()
                            input_field.clear()
                            input_field.send_keys(account[0])
                            print("✅ Used fallback input field method")
                            username_found = True
                            username_field = input_field
                            break
                except:
                    pass
            
            if not username_found:
                print(f"❌ Username field not found for {account[0]}")
                failed_reports += 1
                continue
            
            # UPDATED: Try to find password field with CURRENT selectors
            password_selectors = [
                "//input[@name='password']",
                "//input[@aria-label='Password']",
                "//input[@type='password']",
                "//input[@placeholder='Password']",
                "//input[contains(@class, 'password')]",
                "//input[@id='loginForm']//input[@type='password']",
                "//form//input[@type='password']",
                "//input[2]",  # Second input on page
                "//input[@type='password']",  # Any password field
            ]
            
            password_found = False
            password_field = None
            for selector in password_selectors:
                try:
                    print(f"🔍 Trying password selector: {selector}")
                    password_field = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, selector))
                    )
                    if password_field.is_displayed() and password_field.is_enabled():
                        password_field.clear()
                        password_field.send_keys(account[1])
                        print(f"✅ Password field found with: {selector}")
                        password_found = True
                        break
                except:
                    continue
            
            if not password_found:
                # Try tab navigation as fallback
                try:
                    username_field.send_keys(Keys.TAB)
                    password_field = driver.switch_to.active_element
                    if password_field.get_attribute("type") == "password":
                        password_field.send_keys(account[1])
                        print("✅ Used TAB navigation for password field")
                        password_found = True
                except:
                    pass
            
            if not password_found:
                print(f"❌ Password field not found for {account[0]}")
                failed_reports += 1
                continue
            
            # UPDATED LOGIN BUTTON SELECTORS
            login_button_selectors = [
                "//button[@type='submit']",
                "//button[contains(., 'Log in')]",
                "//button[contains(., 'Log In')]",
                "//button[contains(., 'Sign in')]",
                "//button[contains(., 'Login')]",
                "//div[contains(text(), 'Log in')]",
                "//span[contains(text(), 'Log in')]",
                "//button[contains(@class, 'login')]",
                "//button[contains(@class, 'submit')]",
                "//form//button",
                "//button[.//div[contains(text(), 'Log in')]]",
                "//div[@role='button'][contains(., 'Log in')]",
                "//button",  # Any button
            ]
            
            login_clicked = False
            for selector in login_button_selectors:
                try:
                    login_button = WebDriverWait(driver, 5).until(
                        EC.element_to_be_clickable((By.XPATH, selector))
                    )
                    if "log" in login_button.text.lower() or "sign" in login_button.text.lower() or selector == "//button[@type='submit']":
                        login_button.click()
                        print(f"✅ Login button clicked with: {selector}")
                        login_clicked = True
                        break
                except:
                    continue
            
            if not login_clicked:
                # Try pressing Enter as final fallback
                try:
                    password_field.send_keys(Keys.ENTER)
                    print("✅ Used Enter key as fallback for login")
                    login_clicked = True
                except:
                    print(f"❌ Login button not found for {account[0]}")
                    failed_reports += 1
                    continue
            
            # WAIT FOR LOGIN COMPLETION WITH OTP/2FA HANDLING
            login_success = wait_for_login_completion(driver, account[0])
            
            if not login_success:
                print(f"❌ Login failed for {account[0]}")
                failed_reports += 1
                continue
            
            print("✅ Login successful, proceeding to reporting...")
            
            # Visit target user's page
            target_url = f"https://www.instagram.com/{username}/"
            print(f"🌐 Navigating to target profile: {username}")
            driver.get(target_url)
            time.sleep(5)
            
            # Check if profile exists
            try:
                driver.find_element(By.XPATH, "//h2[contains(text(), 'Sorry') or contains(text(), 'Not Found') or contains(text(), 'This page')]")
                print(f"❌ Target profile '{username}' not found")
                failed_reports += 1
                continue
            except NoSuchElementException:
                pass  # Profile exists
            
            # Report user
            try:
                print("🔍 Looking for options button...")
                option_button_selectors = [
                    "//div[@role='button']//*[local-name()='svg' and (@aria-label='Options' or @aria-label='More options')]",
                    "//button[contains(@aria-label, 'Options') or contains(@aria-label, 'More')]",
                    "//span[contains(text(), 'Options') or contains(text(), 'More')]",
                    "//div[contains(@class, 'more')]//button",
                    "//button[contains(@class, 'more')]",
                    "//svg[@aria-label='More options']",
                    "//div[@role='button'][contains(., '···') or contains(., '...')]",
                ]
                
                if not find_and_click_element(driver, option_button_selectors, 10, "options button"):
                    print(f"❌ Options button not found for {account[0]}")
                    failed_reports += 1
                    continue
                
                time.sleep(2)
                
                print("🔍 Looking for report button...")
                report_button_selectors = [
                    "//button[contains(text(), 'Report')]",
                    "//div[contains(text(), 'Report')]",
                    "//span[contains(text(), 'Report')]",
                    "//button[contains(., 'Report')]",
                ]
                
                if not find_and_click_element(driver, report_button_selectors, 10, "report button"):
                    print(f"❌ Report button not found for {account[0]}")
                    failed_reports += 1
                    continue
                
                time.sleep(2)
                
                print("🔍 Looking for spam reason...")
                spam_button_selectors = [
                    "//button[contains(text(), 'spam') or contains(text(), 'Spam')]",
                    "//div[contains(text(), 'spam') or contains(text(), 'Spam')]",
                    "//span[contains(text(), 'spam') or contains(text(), 'Spam')]",
                ]
                
                if not find_and_click_element(driver, spam_button_selectors, 10, "spam reason"):
                    print(f"❌ Spam reason button not found for {account[0]}")
                    failed_reports += 1
                    continue
                
                time.sleep(2)
                
                print("🔍 Looking for submit button...")
                submit_button_selectors = [
                    "//button[contains(text(), 'Submit') or contains(text(), 'Report')]",
                    "//div[contains(text(), 'Submit') or contains(text(), 'Report')]",
                    "//span[contains(text(), 'Submit') or contains(text(), 'Report')]",
                ]
                
                if not find_and_click_element(driver, submit_button_selectors, 10, "submit button"):
                    print(f"❌ Submit button not found for {account[0]}")
                    failed_reports += 1
                    continue
                
                time.sleep(2)
                
                print(f"✅ Successfully reported {username} using account {account[0]}")
                successful_reports += 1
                    
            except Exception as e:
                print(f"❌ Failed to report using account {account[0]}: {str(e)}")
                failed_reports += 1

        except Exception as e:
            print(f"❌ Error occurred while processing account {account[0]}: {str(e)}")
            failed_reports += 1
            continue

    # Cleanup
    driver.quit()
    
    # Summary
    print("\n" + "="*50)
    print("REPORTING SUMMARY")
    print("="*50)
    print(f"Total accounts processed: {len(accounts)}")
    print(f"Successful reports: {successful_reports}")
    print(f"Failed reports: {failed_reports}")
    success_rate = (successful_reports/len(accounts)*100) if accounts else 0
    print(f"Success rate: {success_rate:.1f}%")
    print("="*50)

# ==================== MAIN APPLICATION ====================

def get_options():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="InstaReport - Licensed Version")
    parser.add_argument("-u", "--username", type=str, default="", help="Username to report.")
    parser.add_argument("-f", "--file", type=str, default="acc.txt", help="Accounts list (Defaults to acc.txt in program directory).")
    return parser.parse_args()

def main():
    """Main application entry point"""
    print("\n" + "="*70)
    print("                    INSTAREPORT - PROTECTED VERSION")
    print("                        Mass Instagram Reporter")
    print("="*70)
    print("🔒 This software is protected by license validation")
    print("📧 Contact developer for licensing information")
    print("="*70)
    
    # Check dependencies
    if not check_dependencies():
        input("\nPress Enter to exit...")
        return
    
    try:
        # Initialize license system and validate
        license_system = LicenseSystem()
        license_system.check_license()
        
        # License check passed, proceed with application
        args = get_options()
        username = args.username
        accounts_file = args.file
        
        show_banner()
        show_loading_screen(3)
        
        if username == "":
            username = input("Username: ")

        show_loading_screen(3)
        report_accounts(username, accounts_file)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
