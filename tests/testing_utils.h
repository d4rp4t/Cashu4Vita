//
// Created by d4rp4t on 20/02/2026.
//

#ifndef TESTING_UTILS_H
#define TESTING_UTILS_H

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define RESET "\033[0m"

#define ASSERT(cond, msg) do {                                       \
total_count++;                                                       \
if (cond) { printf(GREEN "PASS" RESET " %s\n", msg); pass_count++; } \
else      { printf(RED   "FAIL" RESET " %s\n", msg); }               \
} while (0)



#endif //TESTING_UTILS_H
