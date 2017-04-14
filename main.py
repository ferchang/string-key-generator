#Program by hmz2627 -=At=- gmail -=Dot=- com

from tkinter import *
import configparser
from random import *
from math import *
from Crypto import Random
import hashlib
import hmac

#-------------------------------------------

hash_len = 32
def hmac_sha256(key, data):
	return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(length, ikm, salt=b'', info=b''):
	prk = hmac_sha256(salt, ikm)
	t = b""
	okm = b""
	for i in range(ceil(length / hash_len)):
		t = hmac_sha256(prk, t + info + bytes([1+i]))
		okm += t
	return okm[:length]

#-------------------------------------------

class Application(Frame):

	def createWidgets(self):
		
		self.frm0=frm0=Frame(self)
		
		frmt=Frame(frm0)
		txt=Entry(frmt, textvariable=self.keyTxtVar, justify='center')
		self.txt=txt
		txt.bind('<FocusIn>', self.txtFocus)
		txt.pack(fill=BOTH, padx=5, pady=5, side=LEFT, expand=True)
		txt['state']='readonly'
		w = Button(frmt, text="Copy", command=self.copy)
		w.pack(padx=5, pady=5, side=RIGHT, fill=BOTH)
		frmt.pack(fill=BOTH, expand=True)
		
		frmt=Frame(frm0)
		lbl=Label(frmt, text='Required Key strength:')
		lbl.pack(side=LEFT)
		lbl=Label(frmt, text='')
		lbl.pack(side=LEFT)
		self.keyStrengthLbl=lbl#
		frmt.pack()
		frmt=Frame(frm0)
		lbl=Label(frmt, text='Number of possible characters:')
		lbl.pack(side=LEFT)
		lbl=Label(frmt, text='')
		lbl.pack(side=LEFT)
		self.numCharsLbl=lbl#
		frmt.pack()
		frmt=Frame(frm0)
		lbl=Label(frmt, text='Necessary Key length:')
		lbl.pack(side=LEFT)
		lbl=Label(frmt, text='')
		lbl.pack(side=LEFT)
		self.keyLenLbl=lbl#
		frmt.pack()
		w = Button(frm0, text="Generate", command=self.generate, default=ACTIVE)
		w.pack(padx=5, pady=5, side=BOTTOM, fill=X)
		frm0.pack(fill=BOTH)

#-------------------------------------------

	def copy(self):
		print('copy')
		self.root.clipboard_clear()
		self.root.clipboard_append(self.keyTxtVar.get())

#-------------------------------------------

	def txtFocus(self, e):
		self.txt.select_range(0, 999)

#-------------------------------------------

	def myGetRandomBytes(self, n):
		return hkdf(n, Random.new().read(n), self.pepper)

#-------------------------------------------

	def generate(self):
		print('-'*60)
		key=''
		for i in self.generateFairBytes(): key+=self.keyChars[i%self.numChars]
		print(len(key), key)
		self.keyTxtVar.set(key)
		self.txt.focus_set()

#-------------------------------------------

	def isFair(self, rByte):
		fullSetsOfValues=floor(255/self.numChars)
		cond=rByte < (self.numChars * fullSetsOfValues)
		#if not cond: print('byte value', rByte, 'rejected')
		return cond

#-------------------------------------------

	def generateFairBytes(self):
		fairBytes=b''
		loop=True
		while loop:
			print('.', sep='', end='')
			bytes=self.myGetRandomBytes(16)
			for i in range(len(bytes)):
				if self.isFair(bytes[i]):
					fairBytes+=bytes[i:i+1]
					if len(fairBytes)==self.numRequiredKeyChars:
						loop=False
						break
		return fairBytes

#-------------------------------------------

	def showKeyInfo(self):
		self.numCharsLbl['text']=self.numChars
		self.numRequiredKeyChars=ceil((self.keyStrength*log(2))/log(self.numChars))
		self.keyLenLbl['text']=self.numRequiredKeyChars
		self.keyStrengthLbl['text']=self.keyStrength

#-------------------------------------------
			
	def __init__(self, master=None):
	
		self.root=master
		global config, configFile
		configFile=sys.path[0]+'/config.ini'
		config=configparser.RawConfigParser()
		config.read(configFile, encoding='utf-8')
		self.keyChars=config.get('general', 'key_chars').strip().replace('\r', '').replace('\n', '')
		self.numChars=len(self.keyChars)
		self.keyStrength=int(config.get('general', 'key_strength'))

		self.pepper=config.get('general', 'pepper').encode()
		Frame.__init__(self, master)
		self.pack(fill=BOTH)
		master.title('String key genarator')
		self.keyTxtVar=StringVar()
	
		self.createWidgets()
		self.showKeyInfo()

#-------------------------------------------

try:
	root=Tk()
	app=Application(master=root)
	app.mainloop()
except KeyboardInterrupt:
	print('<*******************KeyboardInterrupt*******************>')
