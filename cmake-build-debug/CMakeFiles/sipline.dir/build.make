# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

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
CMAKE_COMMAND = /opt/clion-2019.3.4/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /opt/clion-2019.3.4/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/akarner/rehka/sipline

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/akarner/rehka/sipline/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/sipline.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sipline.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sipline.dir/flags.make

CMakeFiles/sipline.dir/main.c.o: CMakeFiles/sipline.dir/flags.make
CMakeFiles/sipline.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/akarner/rehka/sipline/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/sipline.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sipline.dir/main.c.o   -c /home/akarner/rehka/sipline/main.c

CMakeFiles/sipline.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sipline.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/akarner/rehka/sipline/main.c > CMakeFiles/sipline.dir/main.c.i

CMakeFiles/sipline.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sipline.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/akarner/rehka/sipline/main.c -o CMakeFiles/sipline.dir/main.c.s

# Object files for target sipline
sipline_OBJECTS = \
"CMakeFiles/sipline.dir/main.c.o"

# External object files for target sipline
sipline_EXTERNAL_OBJECTS =

sipline: CMakeFiles/sipline.dir/main.c.o
sipline: CMakeFiles/sipline.dir/build.make
sipline: CMakeFiles/sipline.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/akarner/rehka/sipline/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable sipline"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sipline.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sipline.dir/build: sipline

.PHONY : CMakeFiles/sipline.dir/build

CMakeFiles/sipline.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sipline.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sipline.dir/clean

CMakeFiles/sipline.dir/depend:
	cd /home/akarner/rehka/sipline/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/akarner/rehka/sipline /home/akarner/rehka/sipline /home/akarner/rehka/sipline/cmake-build-debug /home/akarner/rehka/sipline/cmake-build-debug /home/akarner/rehka/sipline/cmake-build-debug/CMakeFiles/sipline.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sipline.dir/depend

