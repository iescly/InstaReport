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
        print("   • Crypto (USDT BSC bep20):0xb14efbbb184efd0b971f0ff2672d452d9f9fa3aa")
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
        print("PayPal: your_paypal@email.com")
        print("USDT (TRC20): TLrJtNx6URBKp6wELxxZiMqWY2UgxWCDyz")
        print("Bitcoin: 3BbHenasptSireuNMbxQ7nofchPFFXhWtr")
        print("Ethereum: 0xb14efbbb184efd0b971f0ff2672d452d9f9fa3aa")
        print()
        print("📧 SEND PAYMENT PROOF TO:")
        print("-"*40)
        print("Email: nhackerraj@gmail.com")
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

def report_accounts(username, accounts_file):
    """Main reporting function"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
    except ImportError:
        print("❌ Selenium not installed. Please run: pip install selenium")
        return
    
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")

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
            
            # Log in
            driver.get("https://www.instagram.com/accounts/login/")
            WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.NAME, "username")))
            
            # Clear and enter credentials
            username_field = driver.find_element(By.NAME, "username")
            password_field = driver.find_element(By.NAME, "password")
            
            username_field.clear()
            username_field.send_keys(account[0])
            password_field.clear()
            password_field.send_keys(account[1])
            
            # Find and click submit button
            submit_button = driver.find_element(By.XPATH, "//button[@type='submit']")
            submit_button.click()
            show_loading_screen(8)

            # Check for login errors
            try:
                error_element = driver.find_element(By.XPATH, "//div[contains(text(), 'incorrect') or contains(text(), 'error')]")
                print(f"Login failed for {account[0]}: Invalid credentials")
                failed_reports += 1
                continue
            except NoSuchElementException:
                pass  # No error, login successful

            # Visit target user's page
            target_url = f"https://www.instagram.com/{username}/"
            driver.get(target_url)
            show_loading_screen(5)
            
            # Check if profile exists
            try:
                driver.find_element(By.XPATH, "//span[contains(text(), 'Sorry, this page')]")
                print(f"Target profile '{username}' not found or private")
                continue
            except NoSuchElementException:
                pass  # Profile exists
            
            # Report user
            try:
                # Look for options button (three dots)
                option_button = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//div[@role='button']//svg[@aria-label='Options' or @aria-label='More options']"))
                )
                option_button.click()
                show_loading_screen(3)
                
                # Click Report button
                report_button = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Report')]"))
                )
                report_button.click()
                show_loading_screen(3)
                
                # Select report reason
                spam_button = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'spam') or contains(text(), 'Spam')]"))
                )
                spam_button.click()
                show_loading_screen(2)
                
                # Submit report
                submit_report = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Submit') or contains(text(), 'Report')]"))
                )
                submit_report.click()
                show_loading_screen(2)
                
                print(f"✅ Successfully reported {username} using account {account[0]}")
                successful_reports += 1
                
                # Close any remaining modals
                try:
                    close_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Close') or contains(text(), 'Done')]")
                    close_button.click()
                except:
                    pass
                    
            except (NoSuchElementException, TimeoutException) as e:
                print(f"❌ Failed to report using account {account[0]}: Report button not found")
                failed_reports += 1

        except (NoSuchElementException, TimeoutException) as e:
            print(f"❌ Error occurred while processing account {account[0]}: {str(e)}")
            failed_reports += 1
            continue
        except Exception as e:
            print(f"❌ Unexpected error with account {account[0]}: {str(e)}")
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
    print(f"Success rate: {(successful_reports/len(accounts)*100):.1f}%")
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

