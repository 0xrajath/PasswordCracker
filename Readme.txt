Program Structure:

	PasswordCracking
		|--src
		|	|--beans
		|	|	|--PasswordFileLine.java
		|	|
		|	|--main
		|		|--PasswordCracker.java
		|
		|--resources
		|	|--dictionaryattack
		|	|	|--john.txt
		|	|
		|	|--hybridattack
		|	|	|--numbersAtEnd.txt
		|	|	|--specialSymbols.txt
		|	|	|--yob.txt
		|	|
		|	|--pswd.txt	
		|
		|--Readme.txt
		
Instructions To Run:
1) Make sure the pswd.txt is in the right directory structure as mentioned above, i.e., resources/pswd.txt 
   I will have already kept the pswd.txt in that location. This instruction is in case you use another pswd.txt
2) I'm attaching some extra resources (Please do not change the file locations in the directory structure):
	-Dictionary file: resources/dictionaryattack/john.txt (Obtained from https://wiki.skullsecurity.org/Passwords)
	-Some extra files I created to help with the program: resources/hybridattack/numbersAtEnd.txt, resources/hybridattack/specialSymbols.txt, resources/hybridattack/yob.txt
3) To run the program, Just run PasswordCracker.java as a Java application (Preferably in an IDE like Eclipse)
4) The Program can take anywhere between 2mins(Average Case) to 5mins(Worst Case) to run depending on the machine it runs on.
5) The output will print on screen(STDOUT) in the format 'username::plaintext password'