Program Structure:

	PasswordCracking
		|--src
		|	|--beans
		|	|	|--PasswordFileLine.java
		|	|
		|	|--main
		|		|--PasswordCracker.java
		|		|--PasswordCrackerExtensive.java
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
2) There are some extra resources :
-Dictionary file: resources/dictionaryattack/john.txt (Obtained from https://wiki.skullsecurity.org/Passwords)
-Some extra files I created to help with the program: resources/hybridattack/numbersAtEnd.txt, resources/hybridattack/specialSymbols.txt, resources/hybridattack/yob.txt
3) To run the program, just run PasswordCracker.java(For a light attack) or PasswordCrackerExstensive.java(For an extensive attack) as a Java application (Preferably in an IDE like Eclipse).
4) The Lite Program can take anywhere between 2mins(Average Case) to 5mins(Worst Case) to run depending on the machine it runs on.
5) The Extensive Program can take much longer and may require higher computational power.
5) The output will print on screen(STDOUT) in the format 'username::plaintext password'