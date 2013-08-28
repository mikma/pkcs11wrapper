The common directory contains the portable code; i.e. the code that is the same
for all platforms. The directories unix and windows contain portable code of
portable code for each base platform. The subdirectories contain platform specific
makefiles, platform specific code and libraries, as well as the binaries.  

If you want to port this project to another platform, we suggest to do it like this.
Chose one of the existing platforms that is most similar to the new platform. Make
a copy of the complete platform directory and give it an appropriate name; e.g.
make a copy of the linux/linux_x64 directory and call it linux/aix for instance. Then 
adapt the platform.h and platform.c files of the copy to fit to your new 
platform.

If you use the included GNU makefiles or MS VC++ projects, you should be able to
compile the shared library or DLL directly. But if you want to use other means,
compiler or make utility, you must define some variables for the preprocessor.
These are:

DEBUG, if you want to compile with debug information and some debug output. 

NO_CALLBACKS, if you want to compile for a VM which does not support the 
	            invocation API or you just do not need callbacks (they are 
	            rarely used by PKCS#11 modules).

