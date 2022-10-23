import re, argparse

def banner():
	print("""                               
               

.__                  .__     ________                                     
|  |__ _____    _____|  |__  \_____  \   ________________________  ___.__.
|  |  \\__  \  /  ___/  |  \  /  ____/  /  ___/\____ \_  __ \__  \<   |  |
|   Y  \/ __ \_\___ \|   Y  \/       \  \___ \ |  |_> >  | \// __ \\___  |
|___|  (____  /____  >___|  /\_______ \/____  >|   __/|__|  (____  / ____|
     \/     \/     \/     \/         \/     \/ |__|              \/\/     


 
Sometimes you need to save time when spraying 
Version 0.1a
@rd_pentest
""")

def main():

	#Show Banner
	banner()

	#Get command line args
	p = argparse.ArgumentParser("./hash2spray.py -f hashes.txt ", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150),description = "Hash Parsing Tool to speed up spraying")

	p.add_argument("-f", "--filename", dest="filename", required=True,help="Enter name of hash/hashcat file to parse")
	p.add_argument("-uh", "--userhashes", dest="userhashes", default="",help="Parse Usernames and Hashes - impacket secrets dump")
	p.add_argument("-up", "--userpasswords", dest="userpasswords", default="",help="Parse Usernames and Passwords - (hashcat --show --username)")
	p.add_argument("-of", "--outputformat", dest="outputformat", default="cme",help="Output Format and command line help cme or meta")

	args = p.parse_args()

	if args.userhashes!="":
		#Code for files with hashes

		#Declare lists
		usernames=[]
		hashes=[]

		#Open file and read in
		file = open(args.filename, 'r')
		lines = file.readlines()
		#Go through each line
		for line in lines:
			#Prepare regex for NTLM
			pwdumpmatch = re.compile('^(\S+?):(.*?:?)([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*?:.*?:\s*$')
			#Run regex against line
			pwdump = pwdumpmatch.match(line.strip())
			#If regex matches
			if pwdump:
				#Parse line using : as delimiter
				splitter = line.strip().split(":")
				#Get the usernames as column 0
				username=splitter[0]
				#Get hash as column 3
				nt=splitter[3]
				ntlm=splitter[2]+":"+splitter[3]

				#Check to see whether username has \ in it which would indicate domain information
				if "\\" in username:
					#Split username on \
					usplitter = username.strip().split("\\")
					#Update username so that no domain info is included
					username=usplitter[1]
					
				#Add username to list
				usernames.append(username)
				#Add hash to list
				if args.outputformat!="":
					if args.outputformat=="cme":
						hashes.append(nt)
					else:
						hashes.append(ntlm)

		#Check length of usernames is greater than 0
		if len(usernames)>0:
			#Open file handler ready to write out usernames
			myfile = open(args.filename+".usernames", mode='wt', encoding='utf-8')
			#Iterate list and write to file
			for lines in usernames:
				myfile.write(lines+"\n")
			#Close file handler
			myfile.close

			#Print success message
			print("[*] Usernames have been written to "+args.filename+".usernames")

		#Check length of hashes is greater than 0
		if len(hashes)>0:
			#Open file handler ready to write out usernames
			myfile = open(args.filename+".hashes", mode='wt', encoding='utf-8')
			#Iterate list and write to file
			for lines in hashes:
				myfile.write(lines+"\n")
			#Close file handler
			myfile.close

			#Print success message
			print("[*] Hashes have been written to "+args.filename+".hashes")

		#Check length of usernames is greater than 0
		if len(usernames)>0:
			#Check to see if output is not CME related
			if args.outputformat!="cme":
				#Open file handler ready to write out usernames
				myfile = open(args.filename+".userpass_file", mode='wt', encoding='utf-8')
				#Iterate usernames and hashes at the same time and write to file
				for x, y in zip(usernames, hashes):
					#Mess about with tuple to remove command and brackets
					a=(x,y)
					a= ' '.join(a)
					myfile.write(str(a)+"\n")
				#Close file handler
				myfile.close

				#Print success message
				print("[*] Metasploit User/Pass file has been written to "+args.filename+".userpass_file")

		if args.outputformat=="cme":
			print ("")
			print ("[*] PitchFork Style Brute Force")
			print ("poetry run crackmapexec rdp targets.txt -u "+args.filename+".usernames"+" -H "+args.filename+".hashes"+ " --no-bruteforce --continue-on-success")
			print ("poetry run crackmapexec smb targets.txt -u "+args.filename+".usernames"+" -H "+args.filename+".hashes"+ " --no-bruteforce --continue-on-success")
		else:
			print ("")
			print ("[*] Metasploit Examples")
			print ("[*] Sniper Style Brute Force")
			print ("msfconsole")
			print ("use scanner/smb/smb_login")
			print ("set user_file '"+args.filename+".usernames"+"'")
			print ("set pass_file '"+args.filename+".hashes"+ "'")
			print ("")
			print ("[*] PitchFork Style Brute Force (Warning may break if usernames have spaces in)")
			print ("msfconsole")
			print ("use scanner/smb/smb_login")
			print ("set userpass_file '"+args.filename+".usernames"+"'")

		exit()

	if args.userpasswords!="":
		usernames=[]
		passwords=[]

		file = open(args.filename, 'r')
		lines = file.readlines()

		for line in lines:
			
			pwdumpmatch = re.compile('^(\S+?):([0-9a-fA-F]{32}):\S+?$')
			
			pwdump = pwdumpmatch.match(line.strip())

			if pwdump:
				splitter = line.strip().split(":")
				username=splitter[0]
				password=splitter[2]

				if "\\" in username:
					usplitter = username.strip().split("\\")
					username=usplitter[1]

				usernames.append(username)
				passwords.append(password)


		if len(usernames)>0:
			myfile = open(args.filename+".hc_usernames", mode='wt', encoding='utf-8')
			for lines in usernames:
				myfile.write(lines+"\n")
			myfile.close

			print("[*] Usernames have been written to "+args.filename+".hc_usernames")

		if len(passwords)>0:
			myfile = open(args.filename+".hc_passwords", mode='wt', encoding='utf-8')
			for lines in passwords:
				myfile.write(lines+"\n")
			myfile.close

			print("[*] Passwords have been written to "+args.filename+".hc_passwords")

		#Check length of usernames is greater than 0
		if len(usernames)>0:
			#Check to see if output is not CME related
			if args.outputformat!="cme":
				#Open file handler ready to write out usernames
				myfile = open(args.filename+".userpass_file", mode='wt', encoding='utf-8')
				#Iterate usernames and passwords at the same time and write to file
				for x, y in zip(usernames, passwords):
					#Mess about with tuple to remove command and brackets
					a=(x,y)
					a= ' '.join(a)
					myfile.write(str(a)+"\n")
				#Close file handler
				myfile.close

				#Print success message
				print("[*] Metasploit User/Pass file has been written to "+args.filename+".userpass_file")

		if args.outputformat=="cme":
			print ("")
			print ("[*] PitchFork Style Brute Force")
			print ("poetry run crackmapexec rdp targets.txt -u "+args.filename+".hc_usernames"+" -p "+args.filename+".hc_passwords"+ " --no-bruteforce --continue-on-success")
			print ("poetry run crackmapexec smb targets.txt -u "+args.filename+".hc_usernames"+" -p "+args.filename+".hc_passwords"+ " --no-bruteforce --continue-on-success")
		else:
			print ("")
			print ("[*] Metasploit Examples")
			print ("[*] Sniper Style Brute Force")
			print ("msfconsole")
			print ("use scanner/smb/smb_login")
			print ("set user_file '"+args.filename+".usernames"+"'")
			print ("set pass_file '"+args.filename+".hashes"+ "'")
			print ("")
			print ("[*] PitchFork Style Brute Force (Warning may break if usernames have spaces in)")
			print ("msfconsole")
			print ("use scanner/smb/smb_login")
			print ("set userpass_file '"+args.filename+".userpass_file"+"'")

		exit()

#Loads up main
if __name__ == '__main__':
	#Call main routine.
	main()