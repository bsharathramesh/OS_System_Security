ECE/CSC 574 Computer Network Security
Project 3: Systems Security
sbangal2@ncsu.edu

Execution Steps:
All the steps till step 3 remains same as mentioned in the project description pdf.

Run as a sudo user.
1. Move pindown.c and Makefile to path /usr/src/linux-2.6.23/security/
2. Execute "make all" in the same path /usr/src/linux-2.6.23/security/
3. After running "make all", pindown.ko and pindown.o file will be generated in the same path.
4. To insert the module into the kernel - insmod ./pindown.ko
5. check the status using the following command - lsmod | grep "pindown"
6. setfattr - setting the access control policy
	setfattr -n "security.pindown" -v "/usr/bin/vim\0" /home/sbangal2/text.txt
	This will set the access control policies, such that the text.txt can be accessed only using the vim application.
7. The status can be checked using getfattr functionality.
8. Try opening the /home/sbangal2/text.txt using the vim application - the application opens using the vim application.
9. Try opening the /home/sbangal2/text.txt using the gedit/vi/cat application - the permission should be denied.


For running the performance test using Iozone tool:
Installation of the tool:
-	wget http://www.iozone.org/src/current/iozone3_394.tar
-	tar xvf iozone3_394/arc/current
-	make
-	make linux

Running the tool:
-	/home/sbangal2/Desktop/iozone3_394/src/current/iozone -a -g 256m -Rb <outputfile_name>

