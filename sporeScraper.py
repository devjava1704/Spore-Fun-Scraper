import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
from tkinter.font import Font
import webbrowser
from telethon import TelegramClient, errors
import requests
import json
from urllib.parse import urlencode
import threading
import asyncio

class TokenMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Spore Token Monitor")
        self.root.geometry("600x430")

        # Variables
        self.api_id = tk.StringVar()
        self.api_hash = tk.StringVar()
        self.telegram_phone = tk.StringVar()
        self.agent_id = tk.IntVar(value=12)
        self.check_interval = tk.IntVar(value=1)
        self.send_to_telegram = tk.BooleanVar(value=False)
        self.telegram_recipient = tk.StringVar(value="@bonkbot_bot")

        self.client = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.monitoring = False
        self.lock = threading.Lock()

        # Build UI
        self.create_widgets()

    def create_widgets(self):
        # Telegram Settings Frame
        telegram_frame = tk.LabelFrame(self.root, text="Telegram Settings", padx=5, pady=5)
        telegram_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nw")

        tk.Checkbutton(telegram_frame, text="Send token to Telegram", variable=self.send_to_telegram, command=self.toggle_telegram_fields).grid(row=0, column=0, columnspan=2, sticky="w")

        tk.Label(telegram_frame, text="API ID:").grid(row=1, column=0, sticky="e")
        self.api_id_entry = tk.Entry(telegram_frame, textvariable=self.api_id, state="disabled", width=25)
        self.api_id_entry.grid(row=1, column=1, sticky="w")

        tk.Label(telegram_frame, text="API HASH:").grid(row=2, column=0, sticky="e")
        self.api_hash_entry = tk.Entry(telegram_frame, textvariable=self.api_hash, state="disabled", width=25)
        self.api_hash_entry.grid(row=2, column=1, sticky="w")

        tk.Label(telegram_frame, text="Phone Number (+prefix):").grid(row=3, column=0, sticky="e")
        self.phone_entry = tk.Entry(telegram_frame, textvariable=self.telegram_phone, state="disabled", width=25)
        self.phone_entry.grid(row=3, column=1, sticky="w")

        tk.Label(telegram_frame, text="Recipient:").grid(row=4, column=0, sticky="e")
        self.telegram_recipient_entry = tk.Entry(telegram_frame, textvariable=self.telegram_recipient, state="disabled", width=25)
        self.telegram_recipient_entry.grid(row=4, column=1, sticky="w")

        link = tk.Label(telegram_frame, text="Find API ID & HASH", fg="blue", cursor="hand2")
        link.grid(row=5, column=0, columnspan=2, pady=5)
        link.bind("<Button-1>", lambda e: webbrowser.open("https://my.telegram.org"))

        # Monitor Settings Frame
        monitor_frame = tk.LabelFrame(self.root, text="Monitor Settings", padx=5, pady=5)
        monitor_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ne")

        tk.Label(monitor_frame, text="Agent ID:").grid(row=0, column=0, sticky="e")
        tk.Entry(monitor_frame, textvariable=self.agent_id, width=15).grid(row=0, column=1, sticky="w")

        tk.Label(monitor_frame, text="Interval (s):").grid(row=1, column=0, sticky="e")
        tk.Entry(monitor_frame, textvariable=self.check_interval, width=15).grid(row=1, column=1, sticky="w")

        # Start/Stop Buttons
        button_frame = tk.Frame(self.root)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        self.start_button = tk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, width=20)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled", width=20)
        self.stop_button.grid(row=0, column=1, padx=5)

        # Log Output
        log_frame = tk.LabelFrame(self.root, text="Log Output", padx=5, pady=5)
        log_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.log_output = scrolledtext.ScrolledText(log_frame, width=70, height=10, state="disabled")
        self.log_output.pack(fill="both", expand=True)

    def toggle_telegram_fields(self):
        state = "normal" if self.send_to_telegram.get() else "disabled"
        self.api_id_entry.config(state=state)
        self.api_hash_entry.config(state=state)
        self.phone_entry.config(state=state)
        self.telegram_recipient_entry.config(state=state)

    def log(self, message):
        self.log_output.config(state="normal")
        self.log_output.insert("end", f"{message}\n")
        self.log_output.see("end")
        self.log_output.config(state="disabled")

    def display_token_popup(self, token):
        popup = Toplevel(self.root)
        popup.title("New Token Detected")
        popup.geometry("300x150")

        tk.Label(popup, text="New Token Detected:", font=("Arial", 12, "bold"), fg="red").pack(pady=5)

        text_widget = tk.Text(popup, height=3, width=35, wrap="word")
        text_widget.insert("1.0", token)
        text_widget.config(state="disabled")
        text_widget.pack(pady=5)

        tk.Button(popup, text="Close", command=popup.destroy).pack(pady=5)

    async def monitor_token_address(self):
        last_token_address = None
        self.monitoring = True

        if self.send_to_telegram.get():
            await self.telegram_login()

        while self.monitoring:
            data = self.fetch_spore_data()
            if data:
                agent = self.find_agent(data, self.agent_id.get())
                if agent:
                    current_token_address = agent.get('tokenAddress', '')
                    self.log(f"Current token address: {current_token_address or 'None'}")

                    if current_token_address != last_token_address:
                        self.log(f"New token detected: {current_token_address}")
                        self.display_token_popup(current_token_address)

                        if self.send_to_telegram.get():
                            await self.send_message_token(current_token_address)
                            self.monitoring = False

                        last_token_address = current_token_address
                else:
                    self.log("No matching agent found.")
            else:
                self.log("Error fetching data.")

            await asyncio.sleep(self.check_interval.get())

    async def telegram_login(self):
        try:
            with self.lock:
                if self.client:
                    await self.client.disconnect()

                self.client = TelegramClient('session', self.api_id.get(), self.api_hash.get())
                await self.client.connect()

                if not await self.client.is_user_authorized():
                    await self.client.send_code_request(self.telegram_phone.get())

                    # Prompt user for the code
                    code_popup = Toplevel(self.root)
                    code_popup.title("Enter Telegram Code")
                    code_popup.geometry("250x100")
                    code_label = tk.Label(code_popup, text="Enter the code sent to your phone:")
                    code_label.pack(pady=5)
                    code_entry = tk.Entry(code_popup)
                    code_entry.pack(pady=5)
                    submit_button = tk.Button(code_popup, text="Submit", command=lambda: self.submit_code(code_entry.get(), code_popup))
                    submit_button.pack(pady=5)
                    self.code = None

                    code_popup.wait_window()

                    try:
                        await self.client.sign_in(self.telegram_phone.get(), self.code)
                    except errors.SessionPasswordNeededError:
                        password_popup = Toplevel(self.root)
                        password_popup.title("Enter Telegram Password")
                        password_popup.geometry("250x100")
                        password_label = tk.Label(password_popup, text="Enter your Telegram password:")
                        password_label.pack(pady=5)
                        password_entry = tk.Entry(password_popup, show="*")
                        password_entry.pack(pady=5)
                        submit_password_button = tk.Button(password_popup, text="Submit", command=lambda: self.submit_password(password_entry.get(), password_popup))
                        submit_password_button.pack(pady=5)
                        self.password = None

                        password_popup.wait_window()
                        await self.client.sign_in(password=self.password)

                self.log("Telegram login successful.")
        except Exception as e:
            self.log(f"Error during Telegram login: {e}")

    def submit_code(self, code, popup):
        self.code = code
        popup.destroy()

    def submit_password(self, password, popup):
        self.password = password
        popup.destroy()

    def start_monitoring(self):
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.monitor_thread = threading.Thread(target=lambda: self.loop.run_until_complete(self.monitor_token_address()), daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        if self.client:
            disconnect_coro = self.client.disconnect
            asyncio.run_coroutine_threadsafe(disconnect_coro(), self.loop)
            self.client = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.log("Monitoring stopped.")

    def fetch_spore_data(self):
        url = 'https://www.spore.fun/api/trpc/status,listAgent'
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'priority': 'u=1, i',
            'referer': 'https://www.spore.fun/',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'trpc-accept': 'application/jsonl',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'x-trpc-source': 'nextjs-react'
        }

        params = {
            'batch': '1',
            'input': '{"0":{"json":null,"meta":{"values":["undefined"]}},"1":{"json":null,"meta":{"values":["undefined"]}}}'
        }

        try:
            full_url = f"{url}?{urlencode(params)}"
            response = requests.get(full_url, headers=headers)
            response.raise_for_status()
            data = [json.loads(line) for line in response.text.strip().split('\n') if line.strip()]
            return data
        except Exception as e:
            self.log(f"Error fetching data: {e}")
            return None

    def find_agent(self, data, agent_id):
        try:
            for item in data:
                if 'json' in item and isinstance(item['json'], list):
                    if len(item['json']) > 2 and isinstance(item['json'][2], list):
                        for sublist in item['json'][2]:
                            if isinstance(sublist, list) and len(sublist) > 0:
                                for agent_list in sublist:
                                    if isinstance(agent_list, list):
                                        for agent in agent_list:
                                            if isinstance(agent, dict) and agent.get('id') == agent_id:
                                                return agent
                                    elif isinstance(agent_list, dict) and agent_list.get('id') == agent_id:
                                        return agent_list
        except Exception as e:
            self.log(f"Error parsing data: {e}")
        return None

    async def send_message_token(self, message):
        try:
            with self.lock:
                await self.client.send_message(self.telegram_recipient.get(), message)
                self.log(f"Token sent to {self.telegram_recipient.get()}: {message}")
        except Exception as e:
            self.log(f"Error sending token to Telegram: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TokenMonitorApp(root)
    root.mainloop()
