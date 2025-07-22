import time
import os
from datetime import datetime

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    clear_screen()
    banner = """
    ╔════════════════════════════════════╗
    ║   LICENSE GATEWAY for InstaReport  ║
    ║           @iEscly                 ║
    ╚════════════════════════════════════╝
    """
    print(banner)

def main_menu():
    display_banner()
    print("Please select an option:")
    print("1: Unban")
    print("2: Ban")
    choice = input("\nEnter your choice (1-2): ")
    return choice

def payment_interface(action):
    display_banner()
    print(f"Select payment method for $500 ({action}):")
    print("1: UPI")
    print("2: Crypto")
    choice = input("\nEnter your choice (1-2): ")
    return choice

def crypto_menu():
    display_banner()
    print("Select cryptocurrency for $500 payment:")
    print("1: USDT")
    print("2: BTC")
    print("3: LTC")
    choice = input("\nEnter your choice (1-3): ")
    return choice

def show_upi_payment(action):
    display_banner()
    print(f"UPI Payment Details ({action}):")
    print("Amount: $500")
    print("UPI ID: Pay7h@ybl")
    print(f"\nPlease complete the payment using the provided UPI ID for {action}.")

def show_crypto_payment(crypto_choice, action):
    crypto_addresses = {
        "1": "USDT(bnb20) Address: 0xd1e005178b87cee6a815cf595ac98c1e9b93402e",
        "2": "BTC Address: bc1q3wzl4mk3wuz77rw5qw48tq4yqa09gzrrrrxkhm",
        "3": "LTC Address: LSv2TWjaopV16hCsZWwyTXAm1RdFcQkSd3"
    }
    crypto_names = {"1": "USDT", "2": "BTC", "3": "LTC"}
    display_banner()
    print(f"{crypto_names[crypto_choice]} Payment Details ({action}):")
    print("Amount: $500")
    print(crypto_addresses[crypto_choice])
    print(f"\nPlease send the payment to the provided address for {action}.")

def await_payment():
    print("\nWaiting for payment confirmation...")
    start_time = time.time()
    timeout = 100  # 100 seconds timeout
    while time.time() - start_time < timeout:
        print(".", end="", flush=True)
        time.sleep(1)
    print("\n\nPayment not detected. Please rerun licence.py to get updated payment details.")
    input("\nPress Enter to continue...")
    return  # Return to main menu

def main():
    while True:
        choice = main_menu()
        
        if choice == "1":
            action = "Unban"
            payment_choice = payment_interface(action)
            
            if payment_choice == "1":
                show_upi_payment(action)
                await_payment()
                
            elif payment_choice == "2":
                crypto_choice = crypto_menu()
                crypto_types = {"1": "USDT", "2": "BTC", "3": "LTC"}
                
                if crypto_choice in crypto_types:
                    show_crypto_payment(crypto_choice, action)
                    await_payment()
                else:
                    display_banner()
                    print("Invalid crypto choice!")
                    input("\nPress Enter to continue...")
                    
            else:
                display_banner()
                print("Invalid payment method!")
                input("\nPress Enter to continue...")
                
        elif choice == "2":
            action = "Ban"
            payment_choice = payment_interface(action)
            
            if payment_choice == "1":
                show_upi_payment(action)
                await_payment()
                
            elif payment_choice == "2":
                crypto_choice = crypto_menu()
                crypto_types = {"1": "USDT", "2": "BTC", "3": "LTC"}
                
                if crypto_choice in crypto_types:
                    show_crypto_payment(crypto_choice, action)
                    await_payment()
                else:
                    display_banner()
                    print("Invalid crypto choice!")
                    input("\nPress Enter to continue...")
                    
            else:
                display_banner()
                print("Invalid payment method!")
                input("\nPress Enter to continue...")
            
        else:
            display_banner()
            print("Invalid choice!")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print("Program terminated by user.")
        exit(0)