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
CMAKE_SOURCE_DIR = /home/wantong/Graduation-Thesis/srsLTE

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wantong/Graduation-Thesis/srsLTE/build

# Include any dependencies generated for this target.
include lib/test/common/CMakeFiles/msg_queue_test.dir/depend.make

# Include the progress variables for this target.
include lib/test/common/CMakeFiles/msg_queue_test.dir/progress.make

# Include the compile flags for this target's objects.
include lib/test/common/CMakeFiles/msg_queue_test.dir/flags.make

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o: lib/test/common/CMakeFiles/msg_queue_test.dir/flags.make
lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o: ../lib/test/common/msg_queue_test.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wantong/Graduation-Thesis/srsLTE/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o"
	cd /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o -c /home/wantong/Graduation-Thesis/srsLTE/lib/test/common/msg_queue_test.cc

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.i"
	cd /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/wantong/Graduation-Thesis/srsLTE/lib/test/common/msg_queue_test.cc > CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.i

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.s"
	cd /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/wantong/Graduation-Thesis/srsLTE/lib/test/common/msg_queue_test.cc -o CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.s

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.requires:

.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.requires

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.provides: lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.requires
	$(MAKE) -f lib/test/common/CMakeFiles/msg_queue_test.dir/build.make lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.provides.build
.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.provides

lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.provides.build: lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o


# Object files for target msg_queue_test
msg_queue_test_OBJECTS = \
"CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o"

# External object files for target msg_queue_test
msg_queue_test_EXTERNAL_OBJECTS =

lib/test/common/msg_queue_test: lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o
lib/test/common/msg_queue_test: lib/test/common/CMakeFiles/msg_queue_test.dir/build.make
lib/test/common/msg_queue_test: lib/src/phy/libsrslte_phy.a
lib/test/common/msg_queue_test: lib/src/common/libsrslte_common.a
lib/test/common/msg_queue_test: /usr/lib/x86_64-linux-gnu/libboost_program_options.so
lib/test/common/msg_queue_test: /usr/lib/x86_64-linux-gnu/libboost_system.so
lib/test/common/msg_queue_test: /usr/lib/x86_64-linux-gnu/libfftw3f.so
lib/test/common/msg_queue_test: /usr/lib/x86_64-linux-gnu/libmbedcrypto.so
lib/test/common/msg_queue_test: lib/test/common/CMakeFiles/msg_queue_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wantong/Graduation-Thesis/srsLTE/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable msg_queue_test"
	cd /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/msg_queue_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
lib/test/common/CMakeFiles/msg_queue_test.dir/build: lib/test/common/msg_queue_test

.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/build

lib/test/common/CMakeFiles/msg_queue_test.dir/requires: lib/test/common/CMakeFiles/msg_queue_test.dir/msg_queue_test.cc.o.requires

.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/requires

lib/test/common/CMakeFiles/msg_queue_test.dir/clean:
	cd /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common && $(CMAKE_COMMAND) -P CMakeFiles/msg_queue_test.dir/cmake_clean.cmake
.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/clean

lib/test/common/CMakeFiles/msg_queue_test.dir/depend:
	cd /home/wantong/Graduation-Thesis/srsLTE/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wantong/Graduation-Thesis/srsLTE /home/wantong/Graduation-Thesis/srsLTE/lib/test/common /home/wantong/Graduation-Thesis/srsLTE/build /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common /home/wantong/Graduation-Thesis/srsLTE/build/lib/test/common/CMakeFiles/msg_queue_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/test/common/CMakeFiles/msg_queue_test.dir/depend
