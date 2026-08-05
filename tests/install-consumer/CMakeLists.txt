cmake_minimum_required(VERSION 3.16)
project(forgebit_install_consumer LANGUAGES C)

find_package(Forgebit 0.1 REQUIRED)

add_executable(forgebit_install_consumer main.c)
target_link_libraries(forgebit_install_consumer PRIVATE Forgebit::forgebit)
