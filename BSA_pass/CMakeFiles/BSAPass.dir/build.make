# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/BSA_test/BSA_pass

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/BSA_test/BSA_pass

# Include any dependencies generated for this target.
include CMakeFiles/BSAPass.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/BSAPass.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/BSAPass.dir/flags.make

CMakeFiles/BSAPass.dir/BSA_pass.cpp.o: CMakeFiles/BSAPass.dir/flags.make
CMakeFiles/BSAPass.dir/BSA_pass.cpp.o: BSA_pass.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BSA_test/BSA_pass/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/BSAPass.dir/BSA_pass.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/BSAPass.dir/BSA_pass.cpp.o -c /root/BSA_test/BSA_pass/BSA_pass.cpp

CMakeFiles/BSAPass.dir/BSA_pass.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/BSAPass.dir/BSA_pass.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BSA_test/BSA_pass/BSA_pass.cpp > CMakeFiles/BSAPass.dir/BSA_pass.cpp.i

CMakeFiles/BSAPass.dir/BSA_pass.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/BSAPass.dir/BSA_pass.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BSA_test/BSA_pass/BSA_pass.cpp -o CMakeFiles/BSAPass.dir/BSA_pass.cpp.s

CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.requires:

.PHONY : CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.requires

CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.provides: CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.requires
	$(MAKE) -f CMakeFiles/BSAPass.dir/build.make CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.provides.build
.PHONY : CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.provides

CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.provides.build: CMakeFiles/BSAPass.dir/BSA_pass.cpp.o


# Object files for target BSAPass
BSAPass_OBJECTS = \
"CMakeFiles/BSAPass.dir/BSA_pass.cpp.o"

# External object files for target BSAPass
BSAPass_EXTERNAL_OBJECTS =

libBSAPass.so: CMakeFiles/BSAPass.dir/BSA_pass.cpp.o
libBSAPass.so: CMakeFiles/BSAPass.dir/build.make
libBSAPass.so: CMakeFiles/BSAPass.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/BSA_test/BSA_pass/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared module libBSAPass.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/BSAPass.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/BSAPass.dir/build: libBSAPass.so

.PHONY : CMakeFiles/BSAPass.dir/build

CMakeFiles/BSAPass.dir/requires: CMakeFiles/BSAPass.dir/BSA_pass.cpp.o.requires

.PHONY : CMakeFiles/BSAPass.dir/requires

CMakeFiles/BSAPass.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/BSAPass.dir/cmake_clean.cmake
.PHONY : CMakeFiles/BSAPass.dir/clean

CMakeFiles/BSAPass.dir/depend:
	cd /root/BSA_test/BSA_pass && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/BSA_test/BSA_pass /root/BSA_test/BSA_pass /root/BSA_test/BSA_pass /root/BSA_test/BSA_pass /root/BSA_test/BSA_pass/CMakeFiles/BSAPass.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/BSAPass.dir/depend

