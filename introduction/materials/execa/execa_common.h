/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Adapted from: Pat Hogan @pathtofile, "exechijack"
 */

#ifndef _EXECA_COMMON_H
#define _EXECA_COMMON_H

#define MAX_FILENAME_LEN 50

struct event {
    int pid;
    char comm[MAX_FILENAME_LEN];
    bool success;
};

#endif // _EXECA_COMMON_H
